# Tenant & User Soft-Delete Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Soft-delete user accounts when single-tenant admins delete their only tenant, with restoration flow on sign-back-in.

**Architecture:** Add soft-delete fields to User model, extend TenantDeletionService to conditionally soft-delete users, add restoration endpoints that validate TenantAdmin role from JWT claims, create frontend restoration modal triggered when user has no active tenant.

**Tech Stack:** .NET 10, EF Core, React 19, TypeScript

---

## Task 1: Add Soft-Delete Fields to User Model

**Files:**
- Modify: `backend/Models/User.cs:26-28`

**Step 1: Add IsDeleted and DeletedAt properties**

Add after line 26 (after `IsSystemAdministrator`):

```csharp
/// <summary>
/// Whether this user account has been soft-deleted.
/// Soft-deleted users can be restored by signing back in.
/// </summary>
public bool IsDeleted { get; set; }

/// <summary>
/// When the user account was soft-deleted.
/// </summary>
public DateTime? DeletedAt { get; set; }
```

**Step 2: Run tests to verify model compiles**

Run: `dotnet build backend`
Expected: Build succeeded

**Step 3: Commit**

```
feat(backend): add soft-delete fields to User model
```

---

## Task 2: Create Database Migration

**Files:**
- Create: `backend/Migrations/[timestamp]_AddUserSoftDelete.cs` (auto-generated)

**Step 1: Create the migration**

Run: `cd backend && dotnet ef migrations add AddUserSoftDelete`
Expected: Migration file created

**Step 2: Verify migration contents**

The migration should add:
- `IsDeleted` bit column with default false
- `DeletedAt` datetime2 nullable column
- Index on `IsDeleted` for query performance

**Step 3: Apply migration locally**

Run: `cd backend && dotnet ef database update`
Expected: Database updated successfully

**Step 4: Commit**

```
feat(backend): add migration for user soft-delete fields
```

---

## Task 3: Extend TenantDeletionResponse DTO

**Files:**
- Modify: `backend/DTOs/DeletionRequests.cs:24-31`

**Step 1: Add UserSoftDeleted property to existing TenantDeletionResponse**

The class exists at lines 24-31. Add the new property:

```csharp
/// <summary>
/// Result of a tenant deletion operation.
/// </summary>
public class TenantDeletionResponse
{
    public bool Success { get; set; }
    /// <summary>
    /// The new active tenant ID for the user, if they were switched to another tenant.
    /// </summary>
    public int? NewActiveTenantId { get; set; }
    /// <summary>
    /// True if the user account was also soft-deleted (single-tenant admin scenario).
    /// Frontend should log out and redirect to homepage.
    /// </summary>
    public bool UserSoftDeleted { get; set; }
}
```

**Step 2: Commit**

```
feat(backend): add UserSoftDeleted flag to TenantDeletionResponse
```

---

## Task 4: Add Restorable Tenant DTOs

**Files:**
- Modify: `backend/DTOs/TenantRequests.cs`

**Step 1: Add RestorableTenantResponse DTO**

Add at end of file:

```csharp
/// <summary>
/// A soft-deleted tenant that the user can restore
/// </summary>
public class RestorableTenantResponse
{
    public int TenantId { get; set; }
    public string Name { get; set; } = string.Empty;
    public DateTime DeletedAt { get; set; }
    public int DaysRemaining { get; set; }
    public RestorableTenantStats Stats { get; set; } = new();
}

public class RestorableTenantStats
{
    public int CollectionCount { get; set; }
    public int ItemCount { get; set; }
    public int CategoryCount { get; set; }
    public int ImageCount { get; set; }
}

/// <summary>
/// Request to restore multiple soft-deleted tenants
/// </summary>
public class RestoreTenantsRequest
{
    public List<int> TenantIds { get; set; } = new();
}

/// <summary>
/// Response from restoring tenants
/// </summary>
public class RestoreTenantsResponse
{
    public List<int> RestoredTenantIds { get; set; } = new();
    public int ActiveTenantId { get; set; }
}

/// <summary>
/// Response from restoring a single tenant
/// </summary>
public class RestoreTenantResponse
{
    public int TenantId { get; set; }
    public string Name { get; set; } = string.Empty;
}
```

**Step 2: Commit**

```
feat(backend): add DTOs for tenant restoration
```

---

## Task 5: Extend TenantDeletionService - Check User Soft-Delete Condition

**Files:**
- Modify: `backend/Services/TenantDeletionService.cs:65-123`

**Step 1: Write failing test**

Create file `backend.tests/Unit/Services/TenantDeletionServiceTests.cs`:

```csharp
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;

namespace OneBigHead.Server.Tests.Unit.Services;

public class TenantDeletionServiceTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly TenantDeletionService _service;
    private readonly Mock<ILogger<TenantDeletionService>> _loggerMock;

    public TenantDeletionServiceTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _loggerMock = new Mock<ILogger<TenantDeletionService>>();

        var tenantRepo = new TenantRepository(_context);
        var tenantUserRepo = new TenantUserRepository(_context);
        var userRepo = new UserRepository(_context);

        _service = new TenantDeletionService(
            _context, tenantRepo, tenantUserRepo, userRepo, _loggerMock.Object);
    }

    public void Dispose() => _context.Dispose();

    [Fact]
    public async Task SoftDeleteTenantAsync_SoftDeletesUser_WhenSingleTenantAdmin()
    {
        // Arrange: User is admin of exactly one tenant, no other memberships
        var tenant = new Tenant { Name = "Only Tenant", HasCompletedWelcome = true };
        _context.Tenants.Add(tenant);
        await _context.SaveChangesAsync();

        var user = new User
        {
            Email = "admin@test.com",
            ActiveTenantId = tenant.Id,
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        var membership = new TenantUser
        {
            UserId = user.Id,
            TenantId = tenant.Id,
            TenantRole = TenantRole.TenantAdmin
        };
        _context.TenantUsers.Add(membership);
        await _context.SaveChangesAsync();

        // Act
        var result = await _service.SoftDeleteTenantAsync(tenant.Id, user.Id);

        // Assert
        Assert.True(result.Success);
        Assert.True(result.UserSoftDeleted);

        var deletedUser = await _context.Users.FindAsync(user.Id);
        Assert.True(deletedUser!.IsDeleted);
        Assert.NotNull(deletedUser.DeletedAt);
    }

    [Fact]
    public async Task SoftDeleteTenantAsync_DoesNotSoftDeleteUser_WhenUserHasOtherTenants()
    {
        // Arrange: User is admin of one tenant but member of another
        var tenant1 = new Tenant { Name = "Tenant 1", HasCompletedWelcome = true };
        var tenant2 = new Tenant { Name = "Tenant 2", HasCompletedWelcome = true };
        _context.Tenants.AddRange(tenant1, tenant2);
        await _context.SaveChangesAsync();

        var user = new User
        {
            Email = "admin@test.com",
            ActiveTenantId = tenant1.Id,
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        _context.TenantUsers.AddRange(
            new TenantUser { UserId = user.Id, TenantId = tenant1.Id, TenantRole = TenantRole.TenantAdmin },
            new TenantUser { UserId = user.Id, TenantId = tenant2.Id, TenantRole = TenantRole.Normal }
        );
        await _context.SaveChangesAsync();

        // Act
        var result = await _service.SoftDeleteTenantAsync(tenant1.Id, user.Id);

        // Assert
        Assert.True(result.Success);
        Assert.False(result.UserSoftDeleted);
        Assert.Equal(tenant2.Id, result.NewActiveTenantId);

        var notDeletedUser = await _context.Users.FindAsync(user.Id);
        Assert.False(notDeletedUser!.IsDeleted);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `dotnet test backend.tests --filter "TenantDeletionServiceTests"`
Expected: FAIL (UserSoftDeleted property doesn't exist yet, or returns false)

**Step 3: Implement user soft-delete logic in SoftDeleteTenantAsync**

In `TenantDeletionService.cs`, modify `SoftDeleteTenantAsync` method. After the existing user-switching loop (around line 116), add:

```csharp
// Check if we should soft-delete the user (single-tenant admin scenario)
bool userSoftDeleted = false;
var deletingUser = await _userRepository.GetByIdAsync(deletedByUserId);
if (deletingUser != null)
{
    // Count user's tenant memberships (excluding the one being deleted)
    var otherMemberships = await _context.TenantUsers
        .CountAsync(tu => tu.UserId == deletedByUserId && tu.TenantId != tenantId);

    // Check if user was TenantAdmin of the deleted tenant
    var wasAdmin = await _context.TenantUsers
        .AnyAsync(tu => tu.UserId == deletedByUserId &&
                        tu.TenantId == tenantId &&
                        tu.TenantRole == TenantRole.TenantAdmin);

    if (otherMemberships == 0 && wasAdmin)
    {
        // Single-tenant admin deleting their only tenant - soft-delete user
        deletingUser.IsDeleted = true;
        deletingUser.DeletedAt = DateTime.UtcNow;
        await _userRepository.UpdateAsync(deletingUser);
        userSoftDeleted = true;

        _logger.LogInformation("User {UserId} soft-deleted after deleting their only tenant {TenantId}",
            deletedByUserId, tenantId);
    }
}

return new TenantDeletionResponse
{
    Success = true,
    NewActiveTenantId = newActiveTenantId,
    UserSoftDeleted = userSoftDeleted
};
```

**Step 4: Run tests to verify they pass**

Run: `dotnet test backend.tests --filter "TenantDeletionServiceTests"`
Expected: PASS

**Step 5: Commit**

```
feat(backend): soft-delete user when single-tenant admin deletes only tenant
```

---

## Task 6: Restore User on Sign-In

**Files:**
- Modify: `backend/Controllers/AuthController.cs:197-239`

**Step 1: Modify GetOrCreateUser to restore soft-deleted users**

In `GetOrCreateUser` method, after finding user by provider ID (around line 201), add restoration logic:

```csharp
// 1. Check for existing linked user by provider ID
var user = await _userRepository.GetByProviderIdAsync(provider, validationResult.Subject!);
if (user != null)
{
    // Restore soft-deleted user
    if (user.IsDeleted)
    {
        user.IsDeleted = false;
        user.DeletedAt = null;
        await _userRepository.UpdateAsync(user);
        _logger.LogInformation("Restored soft-deleted user {UserId} ({Email}) on sign-in",
            user.Id, user.Email);
    }

    var membership = await _tenantUserRepository.GetMembershipAsync(user.Id, user.ActiveTenantId);
    return (user, membership?.TenantRole ?? TenantRole.Normal);
}
```

Also add similar logic for the pending user case (around line 213):

```csharp
if (pendingUser != null && !pendingUser.IsLinked)
{
    // Restore if soft-deleted
    if (pendingUser.IsDeleted)
    {
        pendingUser.IsDeleted = false;
        pendingUser.DeletedAt = null;
        await _userRepository.UpdateAsync(pendingUser);
        _logger.LogInformation("Restored soft-deleted pending user {UserId} on link", pendingUser.Id);
    }

    // Link pending user to this OAuth identity
    // ... existing code
}
```

**Step 2: Commit**

```
feat(backend): restore soft-deleted users on sign-in
```

---

## Task 7: Add Restorable Tenants Endpoint

**Files:**
- Modify: `backend/Controllers/UsersController.cs:165-178` (add after GetDeletionInfo method)

**Step 1: Add AppDbContext dependency**

Add to constructor parameters and field:

```csharp
private readonly AppDbContext _context;

// In constructor:
AppDbContext context,

// In constructor body:
_context = context;
```

**Step 2: Add the endpoint**

```csharp
/// <summary>
/// Get soft-deleted tenants that the current user can restore.
/// Only returns tenants where user was TenantAdmin.
/// </summary>
[HttpGet("me/restorable-tenants")]
[Authorize]
public async Task<IActionResult> GetRestorableTenants()
{
    var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
    if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out var userId))
    {
        return Unauthorized(new { error = "Not authenticated" });
    }

    // Get all tenant memberships where user was TenantAdmin and tenant is soft-deleted
    var restorableTenants = await _context.TenantUsers
        .Include(tu => tu.Tenant)
        .Where(tu => tu.UserId == userId &&
                     tu.TenantRole == TenantRole.TenantAdmin &&
                     tu.Tenant!.IsDeleted)
        .Select(tu => new RestorableTenantResponse
        {
            TenantId = tu.TenantId,
            Name = tu.Tenant!.Name,
            DeletedAt = tu.Tenant.DeletedAt!.Value,
            DaysRemaining = Math.Max(0, 30 - (DateTime.UtcNow - tu.Tenant.DeletedAt!.Value).Days),
            Stats = new RestorableTenantStats
            {
                CollectionCount = _context.Collections.Count(c => c.TenantId == tu.TenantId),
                ItemCount = _context.Items.Count(i => i.TenantId == tu.TenantId),
                CategoryCount = _context.Categories.Count(c => c.TenantId == tu.TenantId),
                ImageCount = _context.StoredImages.Count(i => i.TenantId == tu.TenantId)
            }
        })
        .ToListAsync();

    return Ok(restorableTenants);
}
```

**Step 2: Commit**

```
feat(backend): add endpoint to get restorable tenants
```

---

## Task 8: Add Bulk Tenant Restore Endpoint

**Files:**
- Modify: `backend/Controllers/TenantsController.cs`

**Step 1: Add restore endpoint**

Add after DeleteTenant method:

```csharp
/// <summary>
/// Restore multiple soft-deleted tenants (requires user was TenantAdmin of each).
/// User identity is determined from JWT claims only.
/// </summary>
[HttpPost("restore")]
public async Task<IActionResult> RestoreTenants([FromBody] RestoreTenantsRequest request)
{
    var userId = GetUserId();

    if (request.TenantIds == null || !request.TenantIds.Any())
    {
        return BadRequest(new { error = "At least one tenant ID is required" });
    }

    var restoredIds = new List<int>();
    int? firstActiveTenantId = null;

    foreach (var tenantId in request.TenantIds)
    {
        // Verify user was TenantAdmin of this tenant
        var membership = await _tenantUserRepository.GetMembershipAsync(userId, tenantId);
        if (membership == null || membership.TenantRole != TenantRole.TenantAdmin)
        {
            return Forbid(); // User wasn't admin of this tenant
        }

        var tenant = await _tenantRepository.GetByIdAsync(tenantId);
        if (tenant == null || !tenant.IsDeleted)
        {
            continue; // Skip non-existent or already-active tenants
        }

        // Restore the tenant
        tenant.IsDeleted = false;
        tenant.DeletedAt = null;
        tenant.DeletedByUserId = null;
        await _tenantRepository.UpdateAsync(tenant);

        restoredIds.Add(tenantId);
        if (!firstActiveTenantId.HasValue)
        {
            firstActiveTenantId = tenantId;
        }

        _logger.LogInformation("User {UserId} restored tenant {TenantId} ({TenantName})",
            userId, tenantId, tenant.Name);
    }

    // Set the first restored tenant as active
    if (firstActiveTenantId.HasValue)
    {
        await _userRepository.UpdateActiveTenantAsync(userId, firstActiveTenantId.Value);

        // Generate new JWT with the new tenant
        var user = await _userRepository.GetByIdAsync(userId);
        if (user != null)
        {
            var appToken = _tokenService.GenerateAppToken(user, TenantRole.TenantAdmin);
            SetAuthCookie(appToken);
        }
    }

    return Ok(new RestoreTenantsResponse
    {
        RestoredTenantIds = restoredIds,
        ActiveTenantId = firstActiveTenantId ?? 0
    });
}

/// <summary>
/// Restore a single soft-deleted tenant (requires user was TenantAdmin).
/// </summary>
[HttpPost("{tenantId}/restore")]
public async Task<IActionResult> RestoreTenant(int tenantId)
{
    var userId = GetUserId();

    // Verify user was TenantAdmin of this tenant
    var membership = await _tenantUserRepository.GetMembershipAsync(userId, tenantId);
    if (membership == null || membership.TenantRole != TenantRole.TenantAdmin)
    {
        return Forbid();
    }

    var tenant = await _tenantRepository.GetByIdAsync(tenantId);
    if (tenant == null)
    {
        return NotFound(new { error = "Tenant not found" });
    }

    if (!tenant.IsDeleted)
    {
        return BadRequest(new { error = "Tenant is not deleted" });
    }

    // Restore the tenant
    tenant.IsDeleted = false;
    tenant.DeletedAt = null;
    tenant.DeletedByUserId = null;
    await _tenantRepository.UpdateAsync(tenant);

    _logger.LogInformation("User {UserId} restored tenant {TenantId} ({TenantName})",
        userId, tenantId, tenant.Name);

    return Ok(new RestoreTenantResponse
    {
        TenantId = tenant.Id,
        Name = tenant.Name
    });
}
```

**Step 2: Commit**

```
feat(backend): add endpoints to restore soft-deleted tenants
```

---

## Task 9: Update Frontend Tenants API

**Files:**
- Modify: `frontend/src/api/tenants.ts`

**Step 1: Add new types and API methods**

Add types after existing interfaces:

```typescript
export interface RestorableTenantStats {
  collectionCount: number;
  itemCount: number;
  categoryCount: number;
  imageCount: number;
}

export interface RestorableTenant {
  tenantId: number;
  name: string;
  deletedAt: string;
  daysRemaining: number;
  stats: RestorableTenantStats;
}

export interface RestoreTenantsRequest {
  tenantIds: number[];
}

export interface RestoreTenantsResponse {
  restoredTenantIds: number[];
  activeTenantId: number;
}

export interface RestoreTenantResponse {
  tenantId: number;
  name: string;
}
```

Update TenantDeletionResponse:

```typescript
export interface TenantDeletionResponse {
  success: boolean;
  newActiveTenantId?: number;
  userSoftDeleted?: boolean;
}
```

Add new API methods to tenantsApi object:

```typescript
/**
 * Get soft-deleted tenants the current user can restore
 */
getRestorableTenants(): Promise<RestorableTenant[]> {
  return api.get<RestorableTenant[]>('/users/me/restorable-tenants');
},

/**
 * Restore multiple soft-deleted tenants
 */
restoreTenants(request: RestoreTenantsRequest): Promise<RestoreTenantsResponse> {
  return api.post<RestoreTenantsResponse>('/tenants/restore', request);
},

/**
 * Restore a single soft-deleted tenant
 */
restoreTenant(tenantId: number): Promise<RestoreTenantResponse> {
  return api.post<RestoreTenantResponse>(`/tenants/${tenantId}/restore`);
},
```

**Step 2: Commit**

```
feat(frontend): add API methods for tenant restoration
```

---

## Task 10: Update TenantDeletionSection for User Soft-Delete

**Files:**
- Modify: `frontend/src/components/tenant/TenantDeletionSection.tsx:50-56`

**Step 1: Handle userSoftDeleted flag**

Modify handleConfirmDelete:

```typescript
const handleConfirmDelete = useCallback(async () => {
  const result = await tenantsApi.deleteTenant(tenant.tenantId);
  if (!result.success) {
    throw new Error('Failed to delete workspace');
  }

  if (result.userSoftDeleted) {
    // User account was soft-deleted - log out and redirect to homepage
    await authApi.logout();
    window.location.href = '/';
    return;
  }

  onDeleted();
}, [tenant.tenantId, onDeleted]);
```

Add import for authApi at top:

```typescript
import { tenantsApi, exportApi, authApi } from '../../api';
```

**Step 2: Commit**

```
feat(frontend): handle user soft-delete on tenant deletion
```

---

## Task 11: Create TenantRestorationModal Component

**Files:**
- Create: `frontend/src/components/tenant/TenantRestorationModal.tsx`
- Create: `frontend/src/styles/components/TenantRestorationModal.css`

**Step 1: Create the modal component**

```typescript
import { useState, useEffect } from 'react';
import { tenantsApi } from '../../api';
import type { RestorableTenant } from '../../api/tenants';
import './TenantRestorationModal.css';

interface TenantRestorationModalProps {
  isOpen: boolean;
  onRestoreComplete: () => void;
  onCreateNew: () => void;
}

export function TenantRestorationModal({
  isOpen,
  onRestoreComplete,
  onCreateNew
}: TenantRestorationModalProps) {
  const [restorableTenants, setRestorableTenants] = useState<RestorableTenant[]>([]);
  const [selectedTenantIds, setSelectedTenantIds] = useState<Set<number>>(new Set());
  const [choice, setChoice] = useState<'restore' | 'create'>('restore');
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      loadRestorableTenants();
    }
  }, [isOpen]);

  const loadRestorableTenants = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const tenants = await tenantsApi.getRestorableTenants();
      setRestorableTenants(tenants);
      // Pre-select the first tenant
      if (tenants.length > 0) {
        setSelectedTenantIds(new Set([tenants[0].tenantId]));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load tenants');
    } finally {
      setIsLoading(false);
    }
  };

  const toggleTenant = (tenantId: number) => {
    const newSet = new Set(selectedTenantIds);
    if (newSet.has(tenantId)) {
      newSet.delete(tenantId);
    } else {
      newSet.add(tenantId);
    }
    setSelectedTenantIds(newSet);
  };

  const handleContinue = async () => {
    if (choice === 'create') {
      onCreateNew();
      return;
    }

    if (selectedTenantIds.size === 0) {
      setError('Please select at least one tenant to restore');
      return;
    }

    setIsSubmitting(true);
    setError(null);
    try {
      await tenantsApi.restoreTenants({
        tenantIds: Array.from(selectedTenantIds)
      });
      onRestoreComplete();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to restore tenants');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="restoration-modal-overlay">
      <div className="restoration-modal">
        <h2 className="restoration-modal__title">Welcome Back</h2>
        <p className="restoration-modal__description">
          Your account has been restored. Choose how you'd like to continue:
        </p>

        {error && <div className="restoration-modal__error">{error}</div>}

        {isLoading ? (
          <div className="restoration-modal__loading">Loading...</div>
        ) : (
          <>
            <div className="restoration-modal__options">
              <label className="restoration-modal__option">
                <input
                  type="radio"
                  name="choice"
                  checked={choice === 'restore'}
                  onChange={() => setChoice('restore')}
                />
                <span>Restore existing workspace(s)</span>
              </label>

              {choice === 'restore' && restorableTenants.length > 0 && (
                <div className="restoration-modal__tenants">
                  {restorableTenants.map(tenant => (
                    <label key={tenant.tenantId} className="restoration-modal__tenant">
                      <input
                        type="checkbox"
                        checked={selectedTenantIds.has(tenant.tenantId)}
                        onChange={() => toggleTenant(tenant.tenantId)}
                      />
                      <div className="restoration-modal__tenant-info">
                        <span className="restoration-modal__tenant-name">{tenant.name}</span>
                        <span className="restoration-modal__tenant-stats">
                          {tenant.stats.collectionCount} collections, {tenant.stats.itemCount} items
                        </span>
                        <span className="restoration-modal__tenant-countdown">
                          {tenant.daysRemaining} days until permanent deletion
                        </span>
                      </div>
                    </label>
                  ))}
                </div>
              )}

              <label className="restoration-modal__option">
                <input
                  type="radio"
                  name="choice"
                  checked={choice === 'create'}
                  onChange={() => setChoice('create')}
                />
                <span>Create a new workspace</span>
              </label>
            </div>

            <button
              className="restoration-modal__button"
              onClick={handleContinue}
              disabled={isSubmitting || (choice === 'restore' && selectedTenantIds.size === 0)}
            >
              {isSubmitting ? 'Processing...' : 'Continue'}
            </button>
          </>
        )}
      </div>
    </div>
  );
}

export default TenantRestorationModal;
```

**Step 2: Create CSS file**

```css
.restoration-modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.restoration-modal {
  background: var(--color-bg-primary);
  border-radius: 8px;
  padding: 2rem;
  max-width: 500px;
  width: 90%;
  max-height: 80vh;
  overflow-y: auto;
}

.restoration-modal__title {
  margin: 0 0 0.5rem;
  font-size: 1.5rem;
}

.restoration-modal__description {
  margin: 0 0 1.5rem;
  color: var(--color-text-secondary);
}

.restoration-modal__error {
  background: var(--color-error-bg);
  color: var(--color-error);
  padding: 0.75rem;
  border-radius: 4px;
  margin-bottom: 1rem;
}

.restoration-modal__loading {
  text-align: center;
  padding: 2rem;
  color: var(--color-text-secondary);
}

.restoration-modal__options {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.restoration-modal__option {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  cursor: pointer;
}

.restoration-modal__tenants {
  margin-left: 1.5rem;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  border: 1px solid var(--color-border);
  border-radius: 4px;
  padding: 0.75rem;
  max-height: 200px;
  overflow-y: auto;
}

.restoration-modal__tenant {
  display: flex;
  align-items: flex-start;
  gap: 0.75rem;
  cursor: pointer;
  padding: 0.5rem;
  border-radius: 4px;
}

.restoration-modal__tenant:hover {
  background: var(--color-bg-secondary);
}

.restoration-modal__tenant-info {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.restoration-modal__tenant-name {
  font-weight: 500;
}

.restoration-modal__tenant-stats {
  font-size: 0.875rem;
  color: var(--color-text-secondary);
}

.restoration-modal__tenant-countdown {
  font-size: 0.75rem;
  color: var(--color-warning);
}

.restoration-modal__button {
  width: 100%;
  padding: 0.75rem 1.5rem;
  background: var(--color-primary);
  color: white;
  border: none;
  border-radius: 4px;
  font-size: 1rem;
  cursor: pointer;
}

.restoration-modal__button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.restoration-modal__button:hover:not(:disabled) {
  background: var(--color-primary-hover);
}
```

**Step 3: Export from index**

Update `frontend/src/components/tenant/index.ts`:

```typescript
export { TenantRestorationModal } from './TenantRestorationModal';
```

**Step 4: Commit**

```
feat(frontend): add tenant restoration modal component
```

---

## Task 12: Add No-Tenant Detection to App

**Files:**
- Modify: `frontend/src/App.tsx` or create a wrapper component

**Step 1: Create a NoTenantHandler component**

Create `frontend/src/components/common/NoTenantHandler.tsx`:

```typescript
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser } from '../../contexts/UserContext';
import { tenantsApi } from '../../api';
import { TenantRestorationModal } from '../tenant';

interface NoTenantHandlerProps {
  children: React.ReactNode;
}

/**
 * Handles the case where a user has no active tenant.
 * Shows restoration modal if user has restorable tenants,
 * otherwise redirects to tenant creation.
 */
export function NoTenantHandler({ children }: NoTenantHandlerProps) {
  const { user, loading, refetch } = useUser();
  const navigate = useNavigate();
  const [showRestorationModal, setShowRestorationModal] = useState(false);
  const [hasCheckedTenants, setHasCheckedTenants] = useState(false);

  useEffect(() => {
    const checkTenantStatus = async () => {
      if (loading || !user || hasCheckedTenants) return;

      // Check if user has no active tenants
      const activeTenants = user.tenants?.filter(t => t.hasCompletedWelcome) || [];
      if (activeTenants.length === 0) {
        // Check for restorable tenants
        try {
          const restorable = await tenantsApi.getRestorableTenants();
          if (restorable.length > 0) {
            setShowRestorationModal(true);
          } else {
            // No restorable tenants - redirect to tenant creation
            navigate('/tenants/new');
          }
        } catch {
          // On error, redirect to tenant creation
          navigate('/tenants/new');
        }
      }
      setHasCheckedTenants(true);
    };

    checkTenantStatus();
  }, [user, loading, hasCheckedTenants, navigate]);

  const handleRestoreComplete = () => {
    setShowRestorationModal(false);
    refetch();
    navigate('/collections');
  };

  const handleCreateNew = () => {
    setShowRestorationModal(false);
    navigate('/tenants/new');
  };

  return (
    <>
      {children}
      <TenantRestorationModal
        isOpen={showRestorationModal}
        onRestoreComplete={handleRestoreComplete}
        onCreateNew={handleCreateNew}
      />
    </>
  );
}

export default NoTenantHandler;
```

**Step 2: Wrap app with NoTenantHandler**

In `App.tsx`, wrap the router with the handler (inside UserProvider).

**Step 3: Commit**

```
feat(frontend): add no-tenant detection and restoration flow
```

---

## Task 13: Add Deleted Tenants Section to Settings

**Files:**
- Modify: `frontend/src/views/SettingsView.tsx:473-572`

**Step 1: Add state for deleted tenants**

Add state variables:

```typescript
const [deletedTenants, setDeletedTenants] = useState<RestorableTenant[]>([]);
const [isLoadingDeleted, setIsLoadingDeleted] = useState(false);
const [isRestoringTenant, setIsRestoringTenant] = useState<number | null>(null);
```

Add import:

```typescript
import type { RestorableTenant } from '../api/tenants';
```

**Step 2: Load deleted tenants in renderTenantsSection**

Add loading effect at start of renderTenantsSection:

```typescript
useEffect(() => {
  const loadDeletedTenants = async () => {
    setIsLoadingDeleted(true);
    try {
      const deleted = await tenantsApi.getRestorableTenants();
      setDeletedTenants(deleted);
    } catch {
      // Silently fail - deleted tenants section is optional
    } finally {
      setIsLoadingDeleted(false);
    }
  };

  if (activeSection === 'tenants') {
    loadDeletedTenants();
  }
}, [activeSection]);
```

**Step 3: Add restore handler**

```typescript
const handleRestoreTenant = async (tenantId: number) => {
  setIsRestoringTenant(tenantId);
  try {
    await tenantsApi.restoreTenant(tenantId);
    // Reload the page to refresh tenant list
    window.location.reload();
  } catch (err) {
    setTenantError(err instanceof Error ? err.message : 'Failed to restore tenant');
    setIsRestoringTenant(null);
  }
};
```

**Step 4: Add deleted tenants section to JSX**

After the active tenants list, add:

```tsx
{deletedTenants.length > 0 && (
  <>
    <div className="settings-section__divider" />
    <h3 className="settings-section__subtitle">Deleted Workspaces</h3>
    <p className="settings-section__description">
      These workspaces are scheduled for permanent deletion. Restore them to keep your data.
    </p>
    <div className="settings-tenant-list">
      {deletedTenants.map((tenant) => (
        <div key={tenant.tenantId} className="settings-tenant-card settings-tenant-card--deleted">
          <div className="settings-tenant-card__content">
            <div className="settings-tenant-card__header">
              <h3 className="settings-tenant-card__name">{tenant.name}</h3>
              <span className="settings-tenant-card__badge settings-tenant-card__badge--deleted">
                Deleted
              </span>
            </div>
            <p className="settings-tenant-card__stats">
              {tenant.stats.collectionCount} collections, {tenant.stats.itemCount} items
            </p>
            <p className="settings-tenant-card__countdown">
              {tenant.daysRemaining} days until permanent deletion
            </p>
          </div>
          <div className="settings-tenant-card__actions">
            <button
              className="settings-tenant-card__button settings-tenant-card__button--primary"
              onClick={() => handleRestoreTenant(tenant.tenantId)}
              disabled={isRestoringTenant === tenant.tenantId}
            >
              {isRestoringTenant === tenant.tenantId ? 'Restoring...' : 'Restore'}
            </button>
          </div>
        </div>
      ))}
    </div>
  </>
)}
```

**Step 5: Add CSS for deleted tenant styling**

In `SettingsView.css`:

```css
.settings-tenant-card--deleted {
  opacity: 0.8;
  border-style: dashed;
}

.settings-tenant-card__badge--deleted {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.settings-tenant-card__stats {
  font-size: 0.875rem;
  color: var(--color-text-secondary);
  margin: 0;
}

.settings-tenant-card__countdown {
  font-size: 0.75rem;
  color: var(--color-warning);
  margin: 0.25rem 0 0;
}

.settings-section__subtitle {
  font-size: 1.125rem;
  margin: 1.5rem 0 0.5rem;
}

.settings-section__divider {
  border-top: 1px solid var(--color-border);
  margin: 1.5rem 0;
}
```

**Step 6: Commit**

```
feat(frontend): add deleted tenants section to settings
```

---

## Task 14: Fix RequireAuth for No-Tenant State

**Files:**
- Modify: `frontend/src/components/common/RequireAuth.tsx`

**Step 1: Update RequireAuth to handle no-tenant state**

The current code checks `hasCompletedWelcome` which may not work correctly when user has no tenant. Update the logic:

```typescript
function RequireAuth({ children, skipWelcomeCheck = false, skipTermsCheck = false }: RequireAuthProps) {
  const { user, loading } = useUser();
  const location = useLocation();

  if (loading) {
    return <div className="app__loading">Loading...</div>;
  }

  if (!user) {
    const returnUrl = encodeURIComponent(location.pathname + location.search);
    window.location.href = `/signin?returnUrl=${returnUrl}`;
    return null;
  }

  // Check if user has no active tenants (all may be deleted)
  const hasActiveTenant = user.tenants?.some(t => !t.isDeleted) ?? false;
  if (!hasActiveTenant) {
    // NoTenantHandler will show restoration modal or redirect
    // For now, just render children - NoTenantHandler handles this case
  }

  // Redirect to terms acceptance if user hasn't accepted terms
  if (!skipTermsCheck && !user.hasAcceptedTerms && user.hasCompletedWelcome) {
    return <Navigate to="/terms" replace />;
  }

  // Redirect to welcome wizard if user hasn't completed welcome
  if (!skipWelcomeCheck && !user.hasCompletedWelcome && hasActiveTenant) {
    return <Navigate to="/welcome" replace />;
  }

  return <>{children}</>;
}
```

**Step 2: Commit**

```
fix(frontend): handle no-tenant state in RequireAuth
```

---

## Task 15: Create Tenant Creation Route

**Files:**
- Modify: `frontend/src/router.tsx`

**Step 1: Add route for tenant creation**

Add a route that shows the TenantSetupWizard:

```tsx
{
  path: '/tenants/new',
  element: (
    <RequireAuth skipWelcomeCheck>
      <TenantCreationView />
    </RequireAuth>
  ),
}
```

**Step 2: Create TenantCreationView**

Create `frontend/src/views/TenantCreationView.tsx`:

```tsx
import { useNavigate } from 'react-router-dom';
import TenantSetupWizard from '../components/wizard/TenantSetupWizard';

function TenantCreationView() {
  const navigate = useNavigate();

  const handleComplete = () => {
    window.location.href = '/collections';
  };

  const handleCancel = () => {
    // If user cancels and has no tenant, log them out
    window.location.href = '/';
  };

  return (
    <TenantSetupWizard
      showTerms={false}
      isWelcome={false}
      onComplete={handleComplete}
      onCancel={handleCancel}
    />
  );
}

export default TenantCreationView;
```

**Step 3: Commit**

```
feat(frontend): add dedicated tenant creation route
```

---

## Task 16: Integration Testing

**Files:**
- Create: `backend.tests/Integration/TenantUserSoftDeleteIntegrationTests.cs`

**Step 1: Write integration tests**

```csharp
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using Microsoft.Extensions.Logging;
using Moq;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class TenantUserSoftDeleteIntegrationTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly TenantDeletionService _service;

    public TenantUserSoftDeleteIntegrationTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        var loggerMock = new Mock<ILogger<TenantDeletionService>>();

        var tenantRepo = new TenantRepository(_context);
        var tenantUserRepo = new TenantUserRepository(_context);
        var userRepo = new UserRepository(_context);

        _service = new TenantDeletionService(
            _context, tenantRepo, tenantUserRepo, userRepo, loggerMock.Object);
    }

    public void Dispose() => _context.Dispose();

    [Fact]
    public async Task FullFlow_SingleTenantAdminDeletesTenant_UserIsSoftDeleted()
    {
        // Arrange
        var tenant = new Tenant { Name = "Test", HasCompletedWelcome = true };
        _context.Tenants.Add(tenant);
        await _context.SaveChangesAsync();

        var user = new User
        {
            Email = "test@test.com",
            ActiveTenantId = tenant.Id,
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        _context.TenantUsers.Add(new TenantUser
        {
            UserId = user.Id,
            TenantId = tenant.Id,
            TenantRole = TenantRole.TenantAdmin
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _service.SoftDeleteTenantAsync(tenant.Id, user.Id);

        // Assert
        Assert.True(result.UserSoftDeleted);

        var deletedUser = await _context.Users.FindAsync(user.Id);
        Assert.True(deletedUser!.IsDeleted);
        Assert.NotNull(deletedUser.DeletedAt);

        var deletedTenant = await _context.Tenants.FindAsync(tenant.Id);
        Assert.True(deletedTenant!.IsDeleted);
    }

    [Fact]
    public async Task FullFlow_UserWithMultipleTenants_OnlyTenantDeleted()
    {
        // Arrange
        var tenant1 = new Tenant { Name = "Tenant 1", HasCompletedWelcome = true };
        var tenant2 = new Tenant { Name = "Tenant 2", HasCompletedWelcome = true };
        _context.Tenants.AddRange(tenant1, tenant2);
        await _context.SaveChangesAsync();

        var user = new User
        {
            Email = "test@test.com",
            ActiveTenantId = tenant1.Id,
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        _context.TenantUsers.AddRange(
            new TenantUser { UserId = user.Id, TenantId = tenant1.Id, TenantRole = TenantRole.TenantAdmin },
            new TenantUser { UserId = user.Id, TenantId = tenant2.Id, TenantRole = TenantRole.Normal }
        );
        await _context.SaveChangesAsync();

        // Act
        var result = await _service.SoftDeleteTenantAsync(tenant1.Id, user.Id);

        // Assert
        Assert.False(result.UserSoftDeleted);
        Assert.Equal(tenant2.Id, result.NewActiveTenantId);

        var notDeletedUser = await _context.Users.FindAsync(user.Id);
        Assert.False(notDeletedUser!.IsDeleted);
    }
}
```

**Step 2: Run all tests**

Run: `dotnet test backend.tests`
Expected: All tests pass

**Step 3: Commit**

```
test(backend): add integration tests for user soft-delete flow
```

---

## Task 17: Final Verification and Cleanup

**Step 1: Run full backend test suite**

Run: `dotnet test backend.tests`
Expected: All tests pass

**Step 2: Run frontend linter**

Run: `cd frontend && npm run lint`
Expected: No errors

**Step 3: Build both projects**

Run: `dotnet build backend && cd frontend && npm run build`
Expected: Both build successfully

**Step 4: Manual testing checklist**

- [ ] Create a new user with single tenant
- [ ] Delete the tenant as TenantAdmin
- [ ] Verify logout and redirect to homepage
- [ ] Sign back in
- [ ] Verify restoration modal appears
- [ ] Test "Restore" path - verify tenant is restored
- [ ] Test "Create new" path - verify tenant creation works
- [ ] Go to Settings > My Tenants
- [ ] Verify deleted tenants show with countdown
- [ ] Test restoring from Settings page

**Step 5: Final commit**

```
docs: update design doc with implementation notes
```
