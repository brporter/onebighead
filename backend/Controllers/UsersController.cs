using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class UsersController : ApiControllerBase
{
    private readonly IUserRepository _userRepository;
    private readonly ITenantUserRepository _tenantUserRepository;
    private readonly IUserDeletionService _userDeletionService;
    private readonly AuthenticationSettings _authSettings;
    private readonly ILogger<UsersController> _logger;
    private readonly AppDbContext _context;

    public UsersController(
        IUserRepository userRepository,
        ITenantUserRepository tenantUserRepository,
        IUserDeletionService userDeletionService,
        IOptions<AuthenticationSettings> authSettings,
        ILogger<UsersController> logger,
        AppDbContext context)
    {
        _userRepository = userRepository;
        _tenantUserRepository = tenantUserRepository;
        _userDeletionService = userDeletionService;
        _authSettings = authSettings.Value;
        _logger = logger;
        _context = context;
    }

    /// <summary>
    /// Gets all users in the current tenant.
    /// </summary>
    [HttpGet]
    [Authorize(Policy = "TenantAdmin")]
    public async Task<ActionResult<IEnumerable<TenantUserResponse>>> GetUsers()
    {
        var tenantId = GetTenantId();
        var memberships = await _tenantUserRepository.GetByTenantIdAsync(tenantId);
        var response = memberships.Select(TenantUserResponse.FromTenantUser);
        return Ok(response);
    }

    /// <summary>
    /// Invites a new user to the tenant by email.
    /// Creates a pending user record that will be linked when they first authenticate.
    /// </summary>
    [HttpPost]
    [Authorize(Policy = "TenantAdmin")]
    public async Task<ActionResult<TenantUserResponse>> InviteUser(InviteUserRequest request)
    {
        var tenantId = GetTenantId();

        // Check if user with this email already exists
        var existingUser = await _userRepository.GetByEmailAsync(request.Email);
        if (existingUser != null)
        {
            // Check if they're already a member of this tenant
            var existingMembership = await _tenantUserRepository.GetMembershipAsync(existingUser.Id, tenantId);
            if (existingMembership != null)
            {
                return Conflict(new { error = "A user with this email already exists in your team" });
            }
            // User exists but not in this tenant - add them as a member
            var newMembership = await _tenantUserRepository.CreateAsync(existingUser.Id, tenantId, request.Role);
            _logger.LogInformation("Added existing user {Email} to tenant {TenantId} with role {Role}",
                request.Email, tenantId, request.Role);
            return CreatedAtAction(nameof(GetUsers), null, TenantUserResponse.FromTenantUser(newMembership));
        }

        _logger.LogInformation("Inviting new user {Email} to tenant {TenantId} with role {Role}",
            request.Email, tenantId, request.Role);

        var user = await _userRepository.CreatePendingUserAsync(tenantId, request.Email, request.Role);
        var membership = await _tenantUserRepository.GetMembershipAsync(user.Id, tenantId);

        return CreatedAtAction(nameof(GetUsers), null, TenantUserResponse.FromUser(user, membership?.TenantRole ?? request.Role));
    }

    /// <summary>
    /// Updates a user's role within the tenant.
    /// </summary>
    [HttpPut("{id}/role")]
    [Authorize(Policy = "TenantAdmin")]
    public async Task<IActionResult> UpdateUserRole(int id, UpdateUserRoleRequest request)
    {
        var tenantId = GetTenantId();
        var currentUserId = GetUserId();

        // Prevent users from changing their own role
        if (id == currentUserId)
        {
            return BadRequest(new { error = "You cannot change your own role" });
        }

        // Use atomic operation to update role with admin check
        var result = await _tenantUserRepository.UpdateRoleWithAdminCheckAsync(id, tenantId, request.Role);

        if (result == AdminCheckResult.UserNotFound)
        {
            return NotFound(new { error = "User not found" });
        }

        if (result == AdminCheckResult.WouldRemoveLastAdmin)
        {
            return BadRequest(new { error = "Cannot demote the last admin. Promote another user first." });
        }

        _logger.LogInformation("Updated user {UserId} role to {Role} in tenant {TenantId}",
            id, request.Role, tenantId);

        return NoContent();
    }

    /// <summary>
    /// Removes a user from the tenant.
    /// </summary>
    [HttpDelete("{id}")]
    [Authorize(Policy = "TenantAdmin")]
    public async Task<IActionResult> RemoveUser(int id)
    {
        var tenantId = GetTenantId();
        var currentUserId = GetUserId();

        // Prevent users from removing themselves
        if (id == currentUserId)
        {
            return BadRequest(new { error = "You cannot remove yourself from the team" });
        }

        // Use atomic operation to check admin count and delete
        var result = await _tenantUserRepository.DeleteWithAdminCheckAsync(id, tenantId);

        if (result == AdminCheckResult.UserNotFound)
        {
            return NotFound(new { error = "User not found in this tenant" });
        }

        if (result == AdminCheckResult.WouldRemoveLastAdmin)
        {
            return BadRequest(new { error = "Cannot remove the last admin. Promote another user first." });
        }

        // Check if we need to clean up the user record (if they have no other memberships)
        var remainingMemberships = await _tenantUserRepository.CountUserMembershipsAsync(id);
        if (remainingMemberships == 0)
        {
            await _userRepository.DeleteAsync(id);
        }

        _logger.LogInformation("Removed user {UserId} from tenant {TenantId}", id, tenantId);

        return NoContent();
    }

    /// <summary>
    /// Gets deletion info for the current user's account.
    /// Returns information about tenants that require action before account can be deleted.
    /// </summary>
    [HttpGet("me/deletion-info")]
    public async Task<ActionResult<UserDeletionInfoResponse>> GetDeletionInfo()
    {
        var userId = GetUserId();
        var deletionInfo = await _userDeletionService.GetDeletionInfoAsync(userId);

        if (deletionInfo == null)
        {
            return NotFound(new { error = "User not found" });
        }

        return Ok(deletionInfo);
    }

    /// <summary>
    /// Get soft-deleted tenants that the current user can restore.
    /// Only returns tenants where user was TenantAdmin.
    /// </summary>
    [HttpGet("me/restorable-tenants")]
    public async Task<IActionResult> GetRestorableTenants()
    {
        var userId = GetUserId();
        _logger.LogInformation("GetRestorableTenants called for user {UserId}", userId);

        // First get all tenant memberships for this user where they are TenantAdmin
        var adminMemberships = await _context.TenantUsers
            .Include(tu => tu.Tenant)
            .Where(tu => tu.UserId == userId && tu.TenantRole == TenantRole.TenantAdmin)
            .ToListAsync();

        _logger.LogInformation("User {UserId} has {Count} TenantAdmin memberships", userId, adminMemberships.Count);

        // Filter to only deleted tenants and build response
        var restorableTenants = new List<RestorableTenantResponse>();
        foreach (var membership in adminMemberships)
        {
            if (membership.Tenant == null)
            {
                _logger.LogWarning("TenantUser membership for user {UserId}, tenant {TenantId} has null Tenant", userId, membership.TenantId);
                continue;
            }

            _logger.LogInformation("Checking tenant {TenantId} ({TenantName}): IsDeleted={IsDeleted}",
                membership.TenantId, membership.Tenant.Name, membership.Tenant.IsDeleted);

            if (!membership.Tenant.IsDeleted)
            {
                continue;
            }

            var stats = new RestorableTenantStats
            {
                CollectionCount = await _context.Collections.CountAsync(c => c.TenantId == membership.TenantId),
                ItemCount = await _context.Items.CountAsync(i => i.TenantId == membership.TenantId),
                CategoryCount = await _context.Categories.CountAsync(c => c.TenantId == membership.TenantId),
                ImageCount = await _context.StoredImages.CountAsync(i => i.TenantId == membership.TenantId)
            };

            restorableTenants.Add(new RestorableTenantResponse
            {
                TenantId = membership.TenantId,
                Name = membership.Tenant.Name,
                DeletedAt = membership.Tenant.DeletedAt!.Value,
                DaysRemaining = Math.Max(0, 30 - (DateTime.UtcNow - membership.Tenant.DeletedAt!.Value).Days),
                Stats = stats
            });
        }

        _logger.LogInformation("Returning {Count} restorable tenants for user {UserId}", restorableTenants.Count, userId);
        return Ok(restorableTenants);
    }

    /// <summary>
    /// Deletes the current user's account.
    /// Requires email confirmation and resolution of any blocking tenants.
    /// </summary>
    [HttpDelete("me")]
    public async Task<ActionResult<DeleteUserResponse>> DeleteAccount([FromBody] DeleteUserRequest request)
    {
        var userId = GetUserId();

        var result = await _userDeletionService.DeleteUserAccountAsync(userId, request);

        if (!result.Success)
        {
            return BadRequest(result);
        }

        // Clear the auth cookie to log out the user
        ClearAuthCookie();

        return Ok(result);
    }

    private void ClearAuthCookie()
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = _authSettings.Cookie.Secure,
            SameSite = Enum.Parse<SameSiteMode>(_authSettings.Cookie.SameSite, true),
            Expires = DateTimeOffset.UtcNow.AddDays(-1),
            Path = "/"
        };

        Response.Cookies.Append(_authSettings.Cookie.Name, "", cookieOptions);
    }
}
