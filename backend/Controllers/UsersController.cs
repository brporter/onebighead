using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class UsersController : ApiControllerBase
{
    private readonly IUserRepository _userRepository;
    private readonly ITenantUserRepository _tenantUserRepository;
    private readonly ILogger<UsersController> _logger;

    public UsersController(
        IUserRepository userRepository,
        ITenantUserRepository tenantUserRepository,
        ILogger<UsersController> logger)
    {
        _userRepository = userRepository;
        _tenantUserRepository = tenantUserRepository;
        _logger = logger;
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
}
