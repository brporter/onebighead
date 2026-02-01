using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace OneBigHead.Server.Tests.Integration.Data;

[Trait("Category", "Integration")]
public class UserRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly UserRepository _repository;
    private readonly TenantUserRepository _tenantUserRepository;

    public UserRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning))
            .Options;

        _context = new AppDbContext(options);
        _repository = new UserRepository(_context);
        _tenantUserRepository = new TenantUserRepository(_context);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    private async Task<Tenant> CreateTestTenantAsync()
    {
        var tenant = new Tenant
        {
            Name = "test.example.com",
            CreatedAt = DateTime.UtcNow
        };
        _context.Tenants.Add(tenant);
        await _context.SaveChangesAsync();
        return tenant;
    }

    private async Task<User> CreateTestUserAsync(Tenant tenant, string email, TenantRole role = TenantRole.Normal)
    {
        var user = new User
        {
            ActiveTenantId = tenant.Id,
            Email = email,
            IdentityProvider = IdentityProvider.Microsoft,
            ProviderSubjectId = $"ms-{email}"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        var tenantUser = new TenantUser
        {
            UserId = user.Id,
            TenantId = tenant.Id,
            TenantRole = role
        };
        _context.TenantUsers.Add(tenantUser);
        await _context.SaveChangesAsync();

        return user;
    }

    #region GetByEmailAsync Tests

    [Fact]
    public async Task GetByEmailAsync_ReturnsUser_WhenExists()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        var user = await CreateTestUserAsync(tenant, "test@example.com");

        // Act
        var result = await _repository.GetByEmailAsync("test@example.com");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("test@example.com", result.Email);
        Assert.NotNull(result.ActiveTenant);
    }

    [Fact]
    public async Task GetByEmailAsync_ReturnsNull_WhenNotExists()
    {
        // Act
        var result = await _repository.GetByEmailAsync("nonexistent@example.com");

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region GetByProviderIdAsync Tests

    [Fact]
    public async Task GetByProviderIdAsync_ReturnsUser_WhenExists()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        var user = new User
        {
            ActiveTenantId = tenant.Id,
            Email = "test@example.com",
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "google-sub-123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByProviderIdAsync(IdentityProvider.Google, "google-sub-123");

        // Assert
        Assert.NotNull(result);
        Assert.Equal(IdentityProvider.Google, result.IdentityProvider);
        Assert.Equal("google-sub-123", result.ProviderSubjectId);
    }

    [Fact]
    public async Task GetByProviderIdAsync_ReturnsNull_WhenProviderMismatch()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        var user = new User
        {
            ActiveTenantId = tenant.Id,
            Email = "test@example.com",
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "google-sub-123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Act - same subject ID but different provider
        var result = await _repository.GetByProviderIdAsync(IdentityProvider.Microsoft, "google-sub-123");

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region GetByIdAsync Tests

    [Fact]
    public async Task GetByIdAsync_ReturnsUser_WhenExists()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        var user = await CreateTestUserAsync(tenant, "test@example.com");

        // Act
        var result = await _repository.GetByIdAsync(user.Id);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(user.Id, result.Id);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenNotExists()
    {
        // Act
        var result = await _repository.GetByIdAsync(999);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region CreateWithNewTenantAsync Tests

    [Fact]
    public async Task CreateWithNewTenantAsync_CreatesUserAndTenant()
    {
        // Act
        var result = await _repository.CreateWithNewTenantAsync(
            "newuser@example.com",
            IdentityProvider.Microsoft,
            "ms-new-user-123");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("newuser@example.com", result.Email);
        Assert.Equal(IdentityProvider.Microsoft, result.IdentityProvider);
        Assert.NotNull(result.ActiveTenant);
        Assert.Equal("example.com", result.ActiveTenant.Name);
    }

    [Fact]
    public async Task CreateWithNewTenantAsync_UsesDomainAsTenantName()
    {
        // Act
        var result = await _repository.CreateWithNewTenantAsync(
            "john@contoso.com",
            IdentityProvider.Google,
            "google-123");

        // Assert
        Assert.NotNull(result.ActiveTenant);
        Assert.Equal("contoso.com", result.ActiveTenant.Name);
    }

    [Fact]
    public async Task CreateWithNewTenantAsync_SavesUserToDatabase()
    {
        // Act
        var result = await _repository.CreateWithNewTenantAsync(
            "test@domain.com",
            IdentityProvider.Apple,
            "apple-456");

        // Assert
        var savedUser = await _context.Users.FindAsync(result.Id);
        Assert.NotNull(savedUser);
        Assert.Equal("test@domain.com", savedUser.Email);
    }

    [Fact]
    public async Task CreateWithNewTenantAsync_SavesTenantToDatabase()
    {
        // Act
        var result = await _repository.CreateWithNewTenantAsync(
            "user@newdomain.com",
            IdentityProvider.Microsoft,
            "ms-789");

        // Assert
        var savedTenant = await _context.Tenants.FindAsync(result.ActiveTenantId);
        Assert.NotNull(savedTenant);
        Assert.Equal("newdomain.com", savedTenant.Name);
    }

    [Fact]
    public async Task CreateWithNewTenantAsync_DoesNotCreateDefaultCollection()
    {
        // New behavior: collections are created through setup wizard, not auto-created
        // Act
        var result = await _repository.CreateWithNewTenantAsync(
            "user@test.com",
            IdentityProvider.Microsoft,
            "ms-collection-test");

        // Assert - no collections should be created
        var collections = await _context.Collections
            .Where(c => c.TenantId == result.ActiveTenantId)
            .ToListAsync();

        Assert.Empty(collections);
    }

    [Fact]
    public async Task CreateWithNewTenantAsync_DoesNotCreateUnassignedCategory()
    {
        // New behavior: unassigned category is created per collection during setup wizard
        // Act
        var result = await _repository.CreateWithNewTenantAsync(
            "user@category-test.com",
            IdentityProvider.Google,
            "google-category-test");

        // Assert - no categories should exist
        var categories = await _context.Categories
            .Where(c => c.TenantId == result.ActiveTenantId)
            .ToListAsync();
        Assert.Empty(categories);
    }

    [Fact]
    public async Task CreateWithNewTenantAsync_UsesWholeEmail_WhenNoAtSign()
    {
        // Act
        var result = await _repository.CreateWithNewTenantAsync(
            "localuser",
            IdentityProvider.Apple,
            "apple-local-test");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("localuser", result.Email);

        var tenant = await _context.Tenants.FindAsync(result.ActiveTenantId);
        Assert.NotNull(tenant);
        Assert.Equal("localuser", tenant.Name);
    }

    [Fact]
    public async Task CreateWithNewTenantAsync_SetsFirstUserAsTenantAdmin()
    {
        // Act
        var result = await _repository.CreateWithNewTenantAsync(
            "admin@newdomain.com",
            IdentityProvider.Microsoft,
            "ms-first-user");

        // Assert - check TenantUser record for role
        var tenantUser = await _context.TenantUsers
            .FirstOrDefaultAsync(tu => tu.UserId == result.Id && tu.TenantId == result.ActiveTenantId);
        Assert.NotNull(tenantUser);
        Assert.Equal(TenantRole.TenantAdmin, tenantUser.TenantRole);
    }

    #endregion

    #region GetByTenantIdAsync Tests

    [Fact]
    public async Task GetByTenantIdAsync_ReturnsAllTenantUsers()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        await CreateTestUserAsync(tenant, "user1@example.com", TenantRole.TenantAdmin);
        await CreateTestUserAsync(tenant, "user2@example.com", TenantRole.Normal);

        // Act
        var result = await _repository.GetByTenantIdAsync(tenant.Id);

        // Assert
        var users = result.ToList();
        Assert.Equal(2, users.Count);
        Assert.Contains(users, u => u.Email == "user1@example.com");
        Assert.Contains(users, u => u.Email == "user2@example.com");
    }

    [Fact]
    public async Task GetByTenantIdAsync_ReturnsEmptyForNonExistentTenant()
    {
        // Act
        var result = await _repository.GetByTenantIdAsync(999);

        // Assert
        Assert.Empty(result);
    }

    #endregion

    #region CreatePendingUserAsync Tests

    [Fact]
    public async Task CreatePendingUserAsync_CreatesPendingUser()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();

        // Act
        var result = await _repository.CreatePendingUserAsync(tenant.Id, "pending@example.com", TenantRole.Normal);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("pending@example.com", result.Email);
        Assert.Equal(IdentityProvider.None, result.IdentityProvider);
        Assert.Null(result.ProviderSubjectId);
        Assert.False(result.IsLinked);

        // Verify TenantUser membership
        var tenantUser = await _context.TenantUsers
            .FirstOrDefaultAsync(tu => tu.UserId == result.Id && tu.TenantId == tenant.Id);
        Assert.NotNull(tenantUser);
        Assert.Equal(TenantRole.Normal, tenantUser.TenantRole);
    }

    [Fact]
    public async Task CreatePendingUserAsync_CanCreateAsAdmin()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();

        // Act
        var result = await _repository.CreatePendingUserAsync(tenant.Id, "pendingadmin@example.com", TenantRole.TenantAdmin);

        // Assert
        Assert.NotNull(result);

        // Verify TenantUser membership has admin role
        var tenantUser = await _context.TenantUsers
            .FirstOrDefaultAsync(tu => tu.UserId == result.Id && tu.TenantId == tenant.Id);
        Assert.NotNull(tenantUser);
        Assert.Equal(TenantRole.TenantAdmin, tenantUser.TenantRole);
    }

    #endregion

    #region LinkUserAsync Tests

    [Fact]
    public async Task LinkUserAsync_LinksPendingUser()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        var pendingUser = await _repository.CreatePendingUserAsync(tenant.Id, "tolink@example.com", TenantRole.Normal);
        Assert.False(pendingUser.IsLinked);

        // Act
        var result = await _repository.LinkUserAsync(pendingUser.Id, IdentityProvider.Google, "google-linked-123");

        // Assert
        Assert.NotNull(result);
        Assert.Equal(IdentityProvider.Google, result.IdentityProvider);
        Assert.Equal("google-linked-123", result.ProviderSubjectId);
        Assert.True(result.IsLinked);
    }

    [Fact]
    public async Task LinkUserAsync_ReturnsNull_WhenUserNotFound()
    {
        // Act
        var result = await _repository.LinkUserAsync(999, IdentityProvider.Microsoft, "ms-999");

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region TenantUserRepository - UpdateRoleAsync Tests

    [Fact]
    public async Task TenantUserRepository_UpdateRoleAsync_UpdatesRole()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        var user = await CreateTestUserAsync(tenant, "rolechange@example.com", TenantRole.Normal);

        // Act
        var result = await _tenantUserRepository.UpdateRoleAsync(user.Id, tenant.Id, TenantRole.TenantAdmin);

        // Assert
        Assert.True(result);
        var tenantUser = await _context.TenantUsers
            .FirstOrDefaultAsync(tu => tu.UserId == user.Id && tu.TenantId == tenant.Id);
        Assert.NotNull(tenantUser);
        Assert.Equal(TenantRole.TenantAdmin, tenantUser.TenantRole);
    }

    [Fact]
    public async Task TenantUserRepository_UpdateRoleAsync_ReturnsFalse_WhenMembershipNotFound()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();

        // Act
        var result = await _tenantUserRepository.UpdateRoleAsync(999, tenant.Id, TenantRole.TenantAdmin);

        // Assert
        Assert.False(result);
    }

    #endregion

    #region DeleteByIdAndTenantAsync Tests

    [Fact]
    public async Task DeleteByIdAndTenantAsync_DeletesMembership()
    {
        // Arrange
        var tenant1 = await CreateTestTenantAsync();
        var tenant2 = new Tenant { Name = "second.com" };
        _context.Tenants.Add(tenant2);
        await _context.SaveChangesAsync();

        // Create user with memberships in both tenants
        var user = new User
        {
            ActiveTenantId = tenant1.Id,
            Email = "deleteme@example.com",
            IdentityProvider = IdentityProvider.Microsoft,
            ProviderSubjectId = "ms-delete-me"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        _context.TenantUsers.AddRange(
            new TenantUser { UserId = user.Id, TenantId = tenant1.Id, TenantRole = TenantRole.Normal },
            new TenantUser { UserId = user.Id, TenantId = tenant2.Id, TenantRole = TenantRole.Normal }
        );
        await _context.SaveChangesAsync();

        // Act - delete from tenant1, user should remain because they're still in tenant2
        var result = await _repository.DeleteByIdAndTenantAsync(user.Id, tenant1.Id);

        // Assert
        Assert.True(result);

        // User should still exist
        var existingUser = await _context.Users.FindAsync(user.Id);
        Assert.NotNull(existingUser);

        // But membership in tenant1 should be gone
        var membership1 = await _context.TenantUsers
            .FirstOrDefaultAsync(tu => tu.UserId == user.Id && tu.TenantId == tenant1.Id);
        Assert.Null(membership1);

        // Membership in tenant2 should still exist
        var membership2 = await _context.TenantUsers
            .FirstOrDefaultAsync(tu => tu.UserId == user.Id && tu.TenantId == tenant2.Id);
        Assert.NotNull(membership2);
    }

    [Fact]
    public async Task DeleteByIdAndTenantAsync_DeletesUserWhenLastMembership()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        var user = await CreateTestUserAsync(tenant, "deleteme@example.com");
        var userId = user.Id;

        // Act - delete only membership
        var result = await _repository.DeleteByIdAndTenantAsync(userId, tenant.Id);

        // Assert
        Assert.True(result);

        // User should be deleted since it was their only membership
        var deletedUser = await _context.Users.FindAsync(userId);
        Assert.Null(deletedUser);
    }

    [Fact]
    public async Task DeleteByIdAndTenantAsync_ReturnsFalse_WhenMembershipNotFound()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();

        // Act
        var result = await _repository.DeleteByIdAndTenantAsync(999, tenant.Id);

        // Assert
        Assert.False(result);
    }

    #endregion

    #region TenantUserRepository - CountAdminsInTenantAsync Tests

    [Fact]
    public async Task TenantUserRepository_CountAdminsInTenantAsync_CountsAdmins()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        await CreateTestUserAsync(tenant, "admin1@example.com", TenantRole.TenantAdmin);
        await CreateTestUserAsync(tenant, "admin2@example.com", TenantRole.TenantAdmin);
        await CreateTestUserAsync(tenant, "normal@example.com", TenantRole.Normal);

        // Act
        var count = await _tenantUserRepository.CountAdminsInTenantAsync(tenant.Id);

        // Assert
        Assert.Equal(2, count);
    }

    [Fact]
    public async Task TenantUserRepository_CountAdminsInTenantAsync_ReturnsZero_WhenNoAdmins()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        await CreateTestUserAsync(tenant, "onlynormal@example.com", TenantRole.Normal);

        // Act
        var count = await _tenantUserRepository.CountAdminsInTenantAsync(tenant.Id);

        // Assert
        Assert.Equal(0, count);
    }

    [Fact]
    public async Task TenantUserRepository_CountAdminsInTenantAsync_ReturnsZero_ForNonExistentTenant()
    {
        // Act
        var count = await _tenantUserRepository.CountAdminsInTenantAsync(999);

        // Assert
        Assert.Equal(0, count);
    }

    #endregion
}
