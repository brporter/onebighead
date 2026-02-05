using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Text.RegularExpressions;

namespace OneBigHead.Server.Controllers;

[Route("api/[controller]")]
[Authorize]
public partial class TenantsController : ApiControllerBase
{
    private readonly ITenantRepository _tenantRepository;
    private readonly ITenantUserRepository _tenantUserRepository;
    private readonly IUserRepository _userRepository;
    private readonly ICollectionRepository _collectionRepository;
    private readonly ICategoryRepository _categoryRepository;
    private readonly IItemTemplateRepository _itemTemplateRepository;
    private readonly IThemeRepository _themeRepository;
    private readonly ITokenService _tokenService;
    private readonly ITenantDeletionService _tenantDeletionService;
    private readonly AuthenticationSettings _settings;
    private readonly ILogger<TenantsController> _logger;

    public TenantsController(
        ITenantRepository tenantRepository,
        ITenantUserRepository tenantUserRepository,
        IUserRepository userRepository,
        ICollectionRepository collectionRepository,
        ICategoryRepository categoryRepository,
        IItemTemplateRepository itemTemplateRepository,
        IThemeRepository themeRepository,
        ITokenService tokenService,
        ITenantDeletionService tenantDeletionService,
        IOptions<AuthenticationSettings> settings,
        ILogger<TenantsController> logger)
    {
        _tenantRepository = tenantRepository;
        _tenantUserRepository = tenantUserRepository;
        _userRepository = userRepository;
        _collectionRepository = collectionRepository;
        _categoryRepository = categoryRepository;
        _itemTemplateRepository = itemTemplateRepository;
        _themeRepository = themeRepository;
        _tokenService = tokenService;
        _tenantDeletionService = tenantDeletionService;
        _settings = settings.Value;
        _logger = logger;
    }

    /// <summary>
    /// List all tenant memberships for the current user
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetTenants()
    {
        var userId = GetUserId();
        var memberships = await _tenantUserRepository.GetByUserIdAsync(userId);

        // Filter out deleted tenants
        var response = memberships
            .Where(m => m.Tenant != null && !m.Tenant.IsDeleted)
            .Select(m => new TenantMembershipResponse
            {
                TenantId = m.TenantId,
                TenantName = m.Tenant!.Name,
                TenantRole = m.TenantRole,
                HasCompletedWelcome = m.Tenant.HasCompletedWelcome
            }).ToList();

        return Ok(response);
    }

    /// <summary>
    /// Create a new tenant and add the current user as TenantAdmin.
    /// Note: This creates a tenant without a collection. For full setup with collection, use SetupTenant.
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> CreateTenant([FromBody] CreateTenantRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest(new { error = "Tenant name is required" });
        }

        var userId = GetUserId();

        // Create the new tenant
        var tenant = new Tenant
        {
            Name = request.Name.Trim(),
            HasCompletedWelcome = false,
            CreatedAt = DateTime.UtcNow
        };

        await _tenantRepository.CreateAsync(tenant);

        // Add user as TenantAdmin of the new tenant
        await _tenantUserRepository.CreateAsync(userId, tenant.Id, TenantRole.TenantAdmin);

        _logger.LogInformation("User {UserId} created new tenant {TenantId} ({TenantName})", userId, tenant.Id, tenant.Name);

        return Ok(new CreateTenantResponse
        {
            TenantId = tenant.Id,
            TenantName = tenant.Name,
            TenantRole = TenantRole.TenantAdmin,
            HasCompletedWelcome = false
        });
    }

    /// <summary>
    /// Set up a new tenant with an initial collection.
    /// This is the recommended way to create a new tenant as it includes all necessary setup.
    /// </summary>
    [HttpPost("setup")]
    public async Task<IActionResult> SetupTenant([FromBody] SetupTenantRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.TenantName))
        {
            return BadRequest(new { error = "Tenant name is required" });
        }

        var userId = GetUserId();

        // Create the new tenant
        var tenant = new Tenant
        {
            Name = request.TenantName.Trim(),
            HasCompletedWelcome = true, // Mark as complete since we're setting up fully
            CreatedAt = DateTime.UtcNow
        };

        await _tenantRepository.CreateAsync(tenant);

        // Add user as TenantAdmin of the new tenant
        await _tenantUserRepository.CreateAsync(userId, tenant.Id, TenantRole.TenantAdmin);

        _logger.LogInformation("User {UserId} created new tenant {TenantId} ({TenantName}) via setup", userId, tenant.Id, tenant.Name);

        // Determine collection name (default to "My Collection" if not provided)
        var collectionName = string.IsNullOrWhiteSpace(request.CollectionName)
            ? "My Collection"
            : request.CollectionName.Trim();

        // Get the theme (default to General if not provided or invalid)
        CollectionTheme? theme = null;
        if (request.ThemeId.HasValue)
        {
            theme = await _themeRepository.GetByIdAsync(request.ThemeId.Value);
        }
        if (theme == null)
        {
            // Find the General theme as default
            var themes = await _themeRepository.GetAllAsync();
            theme = themes.FirstOrDefault(t => t.Name == "General") ?? themes.FirstOrDefault();
        }

        // Create the collection
        var slug = GenerateSlug(collectionName);
        var existing = await _collectionRepository.GetBySlugAsync(slug, tenant.Id);
        if (existing != null)
        {
            slug = $"{slug}-{DateTime.UtcNow.Ticks}";
        }

        var collection = new Collection
        {
            TenantId = tenant.Id,
            Name = collectionName,
            Description = request.CollectionDescription?.Trim() ?? string.Empty,
            Slug = slug,
            Visibility = Visibility.Private
        };

        var createdCollection = await _collectionRepository.CreateAsync(collection);

        // Create "Unassigned Items" system category
        var unassignedCategory = new Category
        {
            TenantId = tenant.Id,
            CollectionId = createdCollection.Id,
            Name = "Unassigned Items",
            Description = "Items that have not been assigned to a category",
            IsSystem = true
        };
        await _categoryRepository.CreateAsync(unassignedCategory);

        // Apply theme if available
        if (theme != null)
        {
            // Associate theme templates with collection
            foreach (var themeTemplate in theme.ThemeTemplates)
            {
                await _itemTemplateRepository.AssociateWithCollectionAsync(themeTemplate.ItemTemplateId, createdCollection.Id);
            }

            // Create categories from theme
            await CreateThemeCategoriesAsync(theme, tenant.Id, createdCollection.Id);
        }

        _logger.LogInformation("Created collection {CollectionId} ({CollectionName}) for new tenant {TenantId}",
            createdCollection.Id, createdCollection.Name, tenant.Id);

        // Switch user to the new tenant
        await _userRepository.UpdateActiveTenantAsync(userId, tenant.Id);

        // Generate new JWT with the new tenant
        var user = await _userRepository.GetByIdAsync(userId);
        if (user != null)
        {
            var appToken = _tokenService.GenerateAppToken(user, TenantRole.TenantAdmin);
            SetAuthCookie(appToken);
        }

        return Ok(new SetupTenantResponse
        {
            TenantId = tenant.Id,
            TenantName = tenant.Name,
            TenantRole = TenantRole.TenantAdmin,
            CollectionId = createdCollection.Id,
            CollectionName = createdCollection.Name
        });
    }

    private async Task CreateThemeCategoriesAsync(CollectionTheme theme, int tenantId, int collectionId)
    {
        if (theme.ThemeCategories == null || !theme.ThemeCategories.Any())
            return;

        // Map theme category names to created category IDs
        var categoryNameToIdMap = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        // Sort by parent to ensure parents are created first
        // Use iterative approach to handle arbitrary nesting depth
        var pendingCategories = theme.ThemeCategories.OrderBy(c => c.SortOrder).ToList();
        var maxIterations = pendingCategories.Count * 2; // Safety limit
        var iterations = 0;

        while (pendingCategories.Count > 0 && iterations < maxIterations)
        {
            iterations++;
            var categoriesToProcess = pendingCategories
                .Where(tc => string.IsNullOrEmpty(tc.ParentName) || categoryNameToIdMap.ContainsKey(tc.ParentName))
                .ToList();

            if (!categoriesToProcess.Any())
            {
                _logger.LogWarning("Theme {ThemeId} has orphaned categories that couldn't be created", theme.Id);
                break;
            }

            foreach (var themeCategory in categoriesToProcess)
            {
                int? parentCategoryId = null;
                if (!string.IsNullOrEmpty(themeCategory.ParentName) && categoryNameToIdMap.TryGetValue(themeCategory.ParentName, out var parentId))
                {
                    parentCategoryId = parentId;
                }

                var category = new Category
                {
                    TenantId = tenantId,
                    CollectionId = collectionId,
                    ParentCategoryId = parentCategoryId,
                    Name = themeCategory.Name,
                    Description = themeCategory.Description ?? string.Empty,
                    IsSystem = false
                };

                var created = await _categoryRepository.CreateAsync(category);
                categoryNameToIdMap[themeCategory.Name] = created.Id;
                pendingCategories.Remove(themeCategory);
            }
        }
    }

    private static string GenerateSlug(string name)
    {
        var slug = name.ToLowerInvariant();
        slug = SlugRegex().Replace(slug, "-");
        slug = slug.Trim('-');
        return string.IsNullOrEmpty(slug) ? "collection" : slug;
    }

    [GeneratedRegex(@"[^a-z0-9]+")]
    private static partial Regex SlugRegex();

    /// <summary>
    /// Update a tenant's details (requires TenantAdmin role)
    /// </summary>
    [HttpPut("{tenantId}")]
    public async Task<IActionResult> UpdateTenant(int tenantId, [FromBody] UpdateTenantRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest(new { error = "Tenant name is required" });
        }

        var userId = GetUserId();

        // Verify user is a member of this tenant and has TenantAdmin role
        var membership = await _tenantUserRepository.GetMembershipAsync(userId, tenantId);
        if (membership == null)
        {
            return NotFound(new { error = "Tenant not found" });
        }

        if (membership.TenantRole != TenantRole.TenantAdmin)
        {
            return Forbid();
        }

        // Get and update the tenant
        var tenant = await _tenantRepository.GetByIdAsync(tenantId);
        if (tenant == null)
        {
            return NotFound(new { error = "Tenant not found" });
        }

        tenant.Name = request.Name.Trim();
        await _tenantRepository.UpdateAsync(tenant);

        _logger.LogInformation("User {UserId} updated tenant {TenantId} name to {TenantName}", userId, tenantId, tenant.Name);

        return Ok(new UpdateTenantResponse
        {
            TenantId = tenant.Id,
            TenantName = tenant.Name
        });
    }

    /// <summary>
    /// Switch the current user's active tenant
    /// </summary>
    [HttpPost("{tenantId}/switch")]
    public async Task<IActionResult> SwitchTenant(int tenantId)
    {
        var userId = GetUserId();

        // Verify user is a member of the target tenant
        var membership = await _tenantUserRepository.GetMembershipAsync(userId, tenantId);
        if (membership == null)
        {
            return Forbid();
        }

        // Update user's active tenant
        await _userRepository.UpdateActiveTenantAsync(userId, tenantId);

        // Get updated user and generate new token
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            return NotFound(new { error = "User not found" });
        }

        // Generate new JWT with updated tenant
        var appToken = _tokenService.GenerateAppToken(user, membership.TenantRole);
        SetAuthCookie(appToken);

        _logger.LogInformation("User {UserId} switched to tenant {TenantId}", userId, tenantId);

        return Ok(new SwitchTenantResponse
        {
            Success = true,
            TenantId = tenantId,
            TenantName = membership.Tenant.Name
        });
    }

    /// <summary>
    /// Leave a tenant (remove membership)
    /// </summary>
    [HttpDelete("{tenantId}/membership")]
    public async Task<IActionResult> LeaveTenant(int tenantId)
    {
        var userId = GetUserId();

        // Verify user is a member of this tenant
        var membership = await _tenantUserRepository.GetMembershipAsync(userId, tenantId);
        if (membership == null)
        {
            return NotFound(new { error = "You are not a member of this tenant" });
        }

        // Check if this is the user's only tenant
        var membershipCount = await _tenantUserRepository.CountUserMembershipsAsync(userId);
        if (membershipCount <= 1)
        {
            return BadRequest(new { error = "Cannot leave your only tenant" });
        }

        // If user is TenantAdmin, check if there are other admins
        if (membership.TenantRole == TenantRole.TenantAdmin)
        {
            var adminCount = await _tenantUserRepository.CountAdminsInTenantAsync(tenantId);
            if (adminCount <= 1)
            {
                return BadRequest(new { error = "Cannot leave: you are the only admin in this tenant. Promote another user to admin first." });
            }
        }

        // Get user's current active tenant
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            return NotFound(new { error = "User not found" });
        }

        var wasActiveTenant = user.ActiveTenantId == tenantId;

        // Remove membership
        await _tenantUserRepository.DeleteAsync(userId, tenantId);

        _logger.LogInformation("User {UserId} left tenant {TenantId}", userId, tenantId);

        // If this was their active tenant, we need to switch to another
        if (wasActiveTenant)
        {
            var remainingMemberships = await _tenantUserRepository.GetByUserIdAsync(userId);
            var nextTenant = remainingMemberships.FirstOrDefault();
            if (nextTenant != null)
            {
                await _userRepository.UpdateActiveTenantAsync(userId, nextTenant.TenantId);

                // Reload user and generate new token
                user = await _userRepository.GetByIdAsync(userId);
                if (user != null)
                {
                    var appToken = _tokenService.GenerateAppToken(user, nextTenant.TenantRole);
                    SetAuthCookie(appToken);
                }
            }
        }

        return Ok(new LeaveTenantResponse { Success = true });
    }

    /// <summary>
    /// Get deletion statistics for a tenant (requires TenantAdmin role)
    /// </summary>
    [HttpGet("{tenantId}/stats")]
    public async Task<IActionResult> GetTenantStats(int tenantId)
    {
        var userId = GetUserId();

        // Verify user is a member of this tenant and has TenantAdmin role
        var membership = await _tenantUserRepository.GetMembershipAsync(userId, tenantId);
        if (membership == null)
        {
            return NotFound(new { error = "Tenant not found" });
        }

        if (membership.TenantRole != TenantRole.TenantAdmin)
        {
            return Forbid();
        }

        var stats = await _tenantDeletionService.GetTenantStatsAsync(tenantId);
        if (stats == null)
        {
            return NotFound(new { error = "Tenant not found" });
        }

        return Ok(stats);
    }

    /// <summary>
    /// Soft-delete a tenant (requires TenantAdmin role)
    /// </summary>
    [HttpDelete("{tenantId}")]
    public async Task<IActionResult> DeleteTenant(int tenantId)
    {
        var userId = GetUserId();

        // Verify user is a member of this tenant and has TenantAdmin role
        var membership = await _tenantUserRepository.GetMembershipAsync(userId, tenantId);
        if (membership == null)
        {
            return NotFound(new { error = "Tenant not found" });
        }

        if (membership.TenantRole != TenantRole.TenantAdmin)
        {
            return Forbid();
        }

        var result = await _tenantDeletionService.SoftDeleteTenantAsync(tenantId, userId);
        if (!result.Success)
        {
            return BadRequest(new { error = "Failed to delete tenant" });
        }

        // If user was switched to another tenant, update their token
        if (result.NewActiveTenantId.HasValue)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            var newMembership = await _tenantUserRepository.GetMembershipAsync(userId, result.NewActiveTenantId.Value);
            if (user != null && newMembership != null)
            {
                var appToken = _tokenService.GenerateAppToken(user, newMembership.TenantRole);
                SetAuthCookie(appToken);
            }
        }

        return Ok(result);
    }

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

    /// <summary>
    /// Transfer admin role to another user (requires TenantAdmin role)
    /// </summary>
    [HttpPost("{tenantId}/transfer-admin")]
    public async Task<IActionResult> TransferAdmin(int tenantId, [FromBody] TransferAdminRequest request)
    {
        var userId = GetUserId();

        // Verify user is a member of this tenant and has TenantAdmin role
        var membership = await _tenantUserRepository.GetMembershipAsync(userId, tenantId);
        if (membership == null)
        {
            return NotFound(new { error = "Tenant not found" });
        }

        if (membership.TenantRole != TenantRole.TenantAdmin)
        {
            return Forbid();
        }

        // Verify target user is a member of this tenant
        var targetMembership = await _tenantUserRepository.GetMembershipAsync(request.NewAdminUserId, tenantId);
        if (targetMembership == null)
        {
            return BadRequest(new { error = "Target user is not a member of this tenant" });
        }

        // Promote target user and demote current user
        await _tenantUserRepository.UpdateRoleAsync(request.NewAdminUserId, tenantId, TenantRole.TenantAdmin);
        await _tenantUserRepository.UpdateRoleAsync(userId, tenantId, TenantRole.Normal);

        _logger.LogInformation("User {UserId} transferred admin role to user {NewAdminUserId} in tenant {TenantId}",
            userId, request.NewAdminUserId, tenantId);

        // Update the current user's token with their new role
        var user = await _userRepository.GetByIdAsync(userId);
        if (user != null && user.ActiveTenantId == tenantId)
        {
            var appToken = _tokenService.GenerateAppToken(user, TenantRole.Normal);
            SetAuthCookie(appToken);
        }

        return Ok(new TransferAdminResponse { Success = true });
    }

    private void SetAuthCookie(string token)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = _settings.Cookie.Secure,
            SameSite = Enum.Parse<SameSiteMode>(_settings.Cookie.SameSite, true),
            Expires = DateTimeOffset.UtcNow.AddDays(_settings.Jwt.AbsoluteExpirationDays),
            Path = "/"
        };

        Response.Cookies.Append(_settings.Cookie.Name, token, cookieOptions);
    }
}
