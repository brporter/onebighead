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
    private readonly ILogger<UsersController> _logger;

    public UsersController(IUserRepository userRepository, ILogger<UsersController> logger)
    {
        _userRepository = userRepository;
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
        var users = await _userRepository.GetByTenantIdAsync(tenantId);
        var response = users.Select(TenantUserResponse.FromUser);
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
            if (existingUser.TenantId == tenantId)
            {
                return Conflict(new { error = "A user with this email already exists in your team" });
            }
            return Conflict(new { error = "This email is already associated with another account" });
        }

        _logger.LogInformation("Inviting user {Email} to tenant {TenantId} with role {Role}",
            request.Email, tenantId, request.Role);

        var user = await _userRepository.CreatePendingUserAsync(tenantId, request.Email, request.Role);

        return CreatedAtAction(nameof(GetUsers), null, TenantUserResponse.FromUser(user));
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

        // If demoting to Normal, ensure at least one admin remains
        if (request.Role == TenantRole.Normal)
        {
            var adminCount = await _userRepository.CountAdminsInTenantAsync(tenantId);
            var targetUser = await _userRepository.GetByIdAsync(id);

            if (targetUser?.TenantRole == TenantRole.TenantAdmin && adminCount <= 1)
            {
                return BadRequest(new { error = "Cannot demote the last admin. Promote another user first." });
            }
        }

        var updated = await _userRepository.UpdateRoleAsync(id, tenantId, request.Role);
        if (!updated)
        {
            return NotFound(new { error = "User not found" });
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

        // Check if removing an admin would leave no admins
        var targetUser = await _userRepository.GetByIdAsync(id);
        if (targetUser?.TenantRole == TenantRole.TenantAdmin)
        {
            var adminCount = await _userRepository.CountAdminsInTenantAsync(tenantId);
            if (adminCount <= 1)
            {
                return BadRequest(new { error = "Cannot remove the last admin. Promote another user first." });
            }
        }

        var deleted = await _userRepository.DeleteByIdAndTenantAsync(id, tenantId);
        if (!deleted)
        {
            return NotFound(new { error = "User not found" });
        }

        _logger.LogInformation("Removed user {UserId} from tenant {TenantId}", id, tenantId);

        return NoContent();
    }
}
