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
    private readonly IWorkspaceUserRepository _workspaceUserRepository;
    private readonly IUserDeletionService _userDeletionService;
    private readonly AuthenticationSettings _authSettings;
    private readonly ILogger<UsersController> _logger;
    private readonly AppDbContext _context;

    public UsersController(
        IUserRepository userRepository,
        IWorkspaceUserRepository workspaceUserRepository,
        IUserDeletionService userDeletionService,
        IOptions<AuthenticationSettings> authSettings,
        ILogger<UsersController> logger,
        AppDbContext context)
    {
        _userRepository = userRepository;
        _workspaceUserRepository = workspaceUserRepository;
        _userDeletionService = userDeletionService;
        _authSettings = authSettings.Value;
        _logger = logger;
        _context = context;
    }

    /// <summary>
    /// Gets all users in the current workspace.
    /// </summary>
    [HttpGet]
    [Authorize(Policy = "WorkspaceAdmin")]
    public async Task<ActionResult<IEnumerable<WorkspaceUserResponse>>> GetUsers()
    {
        var workspaceId = GetWorkspaceId();
        var memberships = await _workspaceUserRepository.GetByWorkspaceIdAsync(workspaceId);
        var response = memberships.Select(WorkspaceUserResponse.FromWorkspaceUser);
        return Ok(response);
    }

    /// <summary>
    /// Invites a new user to the workspace by email.
    /// Creates a pending user record that will be linked when they first authenticate.
    /// </summary>
    [HttpPost]
    [Authorize(Policy = "WorkspaceAdmin")]
    public async Task<ActionResult<WorkspaceUserResponse>> InviteUser(InviteUserRequest request)
    {
        var workspaceId = GetWorkspaceId();

        // Check if user with this email already exists
        var existingUser = await _userRepository.GetByEmailAsync(request.Email);
        if (existingUser != null)
        {
            // Check if they're already a member of this workspace
            var existingMembership = await _workspaceUserRepository.GetMembershipAsync(existingUser.Id, workspaceId);
            if (existingMembership != null)
            {
                return Conflict(new { error = "A user with this email already exists in your team" });
            }
            // User exists but not in this workspace - add them as a member
            var newMembership = await _workspaceUserRepository.CreateAsync(existingUser.Id, workspaceId, request.Role);
            _logger.LogInformation("Added existing user {Email} to workspace {WorkspaceId} with role {Role}",
                request.Email, workspaceId, request.Role);
            return CreatedAtAction(nameof(GetUsers), null, WorkspaceUserResponse.FromWorkspaceUser(newMembership));
        }

        _logger.LogInformation("Inviting new user {Email} to workspace {WorkspaceId} with role {Role}",
            request.Email, workspaceId, request.Role);

        var user = await _userRepository.CreatePendingUserAsync(workspaceId, request.Email, request.Role);
        var membership = await _workspaceUserRepository.GetMembershipAsync(user.Id, workspaceId);

        return CreatedAtAction(nameof(GetUsers), null, WorkspaceUserResponse.FromUser(user, membership?.WorkspaceRole ?? request.Role));
    }

    /// <summary>
    /// Updates a user's role within the workspace.
    /// </summary>
    [HttpPut("{id}/role")]
    [Authorize(Policy = "WorkspaceAdmin")]
    public async Task<IActionResult> UpdateUserRole(int id, UpdateUserRoleRequest request)
    {
        var workspaceId = GetWorkspaceId();
        var currentUserId = GetUserId();

        // Prevent users from changing their own role
        if (id == currentUserId)
        {
            return BadRequest(new { error = "You cannot change your own role" });
        }

        // Use atomic operation to update role with admin check
        var result = await _workspaceUserRepository.UpdateRoleWithAdminCheckAsync(id, workspaceId, request.Role);

        if (result == AdminCheckResult.UserNotFound)
        {
            return NotFound(new { error = "User not found" });
        }

        if (result == AdminCheckResult.WouldRemoveLastAdmin)
        {
            return BadRequest(new { error = "Cannot demote the last admin. Promote another user first." });
        }

        _logger.LogInformation("Updated user {UserId} role to {Role} in workspace {WorkspaceId}",
            id, request.Role, workspaceId);

        return NoContent();
    }

    /// <summary>
    /// Removes a user from the workspace.
    /// </summary>
    [HttpDelete("{id}")]
    [Authorize(Policy = "WorkspaceAdmin")]
    public async Task<IActionResult> RemoveUser(int id)
    {
        var workspaceId = GetWorkspaceId();
        var currentUserId = GetUserId();

        // Prevent users from removing themselves
        if (id == currentUserId)
        {
            return BadRequest(new { error = "You cannot remove yourself from the team" });
        }

        // Use atomic operation to check admin count and delete
        var result = await _workspaceUserRepository.DeleteWithAdminCheckAsync(id, workspaceId);

        if (result == AdminCheckResult.UserNotFound)
        {
            return NotFound(new { error = "User not found in this workspace" });
        }

        if (result == AdminCheckResult.WouldRemoveLastAdmin)
        {
            return BadRequest(new { error = "Cannot remove the last admin. Promote another user first." });
        }

        // Check if we need to clean up the user record (if they have no other memberships)
        var remainingMemberships = await _workspaceUserRepository.CountUserMembershipsAsync(id);
        if (remainingMemberships == 0)
        {
            await _userRepository.DeleteAsync(id);
        }

        _logger.LogInformation("Removed user {UserId} from workspace {WorkspaceId}", id, workspaceId);

        return NoContent();
    }

    /// <summary>
    /// Gets deletion info for the current user's account.
    /// Returns information about workspaces that require action before account can be deleted.
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
    /// Get soft-deleted workspaces that the current user can restore.
    /// Only returns workspaces where user was WorkspaceAdmin.
    /// </summary>
    [HttpGet("me/restorable-workspaces")]
    public async Task<IActionResult> GetRestorableWorkspaces()
    {
        var userId = GetUserId();
        _logger.LogInformation("GetRestorableWorkspaces called for user {UserId}", userId);

        // First get all workspace memberships for this user where they are WorkspaceAdmin
        var adminMemberships = await _context.WorkspaceUsers
            .Include(wu => wu.Workspace)
            .Where(wu => wu.UserId == userId && wu.WorkspaceRole == WorkspaceRole.WorkspaceAdmin)
            .ToListAsync();

        _logger.LogInformation("User {UserId} has {Count} WorkspaceAdmin memberships", userId, adminMemberships.Count);

        // Filter to only deleted workspaces and build response
        var restorableWorkspaces = new List<RestorableWorkspaceResponse>();
        foreach (var membership in adminMemberships)
        {
            if (membership.Workspace == null)
            {
                _logger.LogWarning("WorkspaceUser membership for user {UserId}, workspace {WorkspaceId} has null Workspace", userId, membership.WorkspaceId);
                continue;
            }

            _logger.LogInformation("Checking workspace {WorkspaceId} ({WorkspaceName}): IsDeleted={IsDeleted}",
                membership.WorkspaceId, membership.Workspace.Name, membership.Workspace.IsDeleted);

            if (!membership.Workspace.IsDeleted)
            {
                continue;
            }

            var stats = new RestorableWorkspaceStats
            {
                CollectionCount = await _context.Collections.CountAsync(c => c.WorkspaceId == membership.WorkspaceId),
                ItemCount = await _context.Items.CountAsync(i => i.WorkspaceId == membership.WorkspaceId),
                CategoryCount = await _context.Categories.CountAsync(c => c.WorkspaceId == membership.WorkspaceId),
                ImageCount = await _context.StoredImages.CountAsync(i => i.WorkspaceId == membership.WorkspaceId)
            };

            restorableWorkspaces.Add(new RestorableWorkspaceResponse
            {
                WorkspaceId = membership.WorkspaceId,
                Name = membership.Workspace.Name,
                DeletedAt = membership.Workspace.DeletedAt!.Value,
                DaysRemaining = Math.Max(0, 30 - (DateTime.UtcNow - membership.Workspace.DeletedAt!.Value).Days),
                Stats = stats
            });
        }

        _logger.LogInformation("Returning {Count} restorable workspaces for user {UserId}", restorableWorkspaces.Count, userId);
        return Ok(restorableWorkspaces);
    }

    /// <summary>
    /// Deletes the current user's account.
    /// Requires email confirmation and resolution of any blocking workspaces.
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
