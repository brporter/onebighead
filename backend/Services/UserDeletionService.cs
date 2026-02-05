using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services;

public interface IUserDeletionService
{
    Task<UserDeletionInfoResponse?> GetDeletionInfoAsync(int userId);
    Task<TransferAdminResponse> TransferAdminRoleAsync(int workspaceId, int fromUserId, int toUserId);
    Task<DeleteUserResponse> DeleteUserAccountAsync(int userId, DeleteUserRequest request);
}

public class UserDeletionService : IUserDeletionService
{
    private readonly AppDbContext _context;
    private readonly IUserRepository _userRepository;
    private readonly IWorkspaceUserRepository _workspaceUserRepository;
    private readonly IWorkspaceDeletionService _workspaceDeletionService;
    private readonly ILogger<UserDeletionService> _logger;

    public UserDeletionService(
        AppDbContext context,
        IUserRepository userRepository,
        IWorkspaceUserRepository workspaceUserRepository,
        IWorkspaceDeletionService workspaceDeletionService,
        ILogger<UserDeletionService> logger)
    {
        _context = context;
        _userRepository = userRepository;
        _workspaceUserRepository = workspaceUserRepository;
        _workspaceDeletionService = workspaceDeletionService;
        _logger = logger;
    }

    public async Task<UserDeletionInfoResponse?> GetDeletionInfoAsync(int userId)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            return null;
        }

        var memberships = await _workspaceUserRepository.GetByUserIdAsync(userId);
        var membershipInfos = new List<WorkspaceMembershipDeletionInfo>();
        var workspacesRequiringAction = 0;

        foreach (var membership in memberships)
        {
            // Skip deleted workspaces
            if (membership.Workspace?.IsDeleted == true)
            {
                continue;
            }

            var userCount = await _workspaceUserRepository.CountMembersInWorkspaceAsync(membership.WorkspaceId);
            var adminCount = await _workspaceUserRepository.CountAdminsInWorkspaceAsync(membership.WorkspaceId);
            var isOnlyUser = userCount == 1;
            var isOnlyAdmin = membership.WorkspaceRole == WorkspaceRole.WorkspaceAdmin && adminCount == 1 && userCount > 1;

            var blockerReason = DeletionBlockerReason.None;
            var canLeave = true;

            if (isOnlyUser)
            {
                blockerReason = DeletionBlockerReason.SoleUser;
                canLeave = false;
                workspacesRequiringAction++;
            }
            else if (isOnlyAdmin)
            {
                blockerReason = DeletionBlockerReason.SoleAdmin;
                canLeave = false;
                workspacesRequiringAction++;
            }

            // Get other users in the workspace for admin transfer selection
            var otherUsers = new List<UserBasicInfo>();
            if (isOnlyAdmin)
            {
                var workspaceUsers = await _context.WorkspaceUsers
                    .Include(wu => wu.User)
                    .Where(wu => wu.WorkspaceId == membership.WorkspaceId && wu.UserId != userId)
                    .ToListAsync();

                otherUsers = workspaceUsers
                    .Where(wu => wu.User != null)
                    .Select(wu => new UserBasicInfo
                    {
                        UserId = wu.UserId,
                        Email = wu.User!.Email
                    })
                    .ToList();
            }

            membershipInfos.Add(new WorkspaceMembershipDeletionInfo
            {
                WorkspaceId = membership.WorkspaceId,
                WorkspaceName = membership.Workspace?.Name ?? "Unknown",
                Role = membership.WorkspaceRole,
                IsOnlyUser = isOnlyUser,
                IsOnlyAdmin = isOnlyAdmin,
                UserCount = userCount,
                CanLeave = canLeave,
                BlockerReason = blockerReason,
                OtherUsers = otherUsers
            });
        }

        return new UserDeletionInfoResponse
        {
            UserId = userId,
            Email = user.Email,
            WorkspaceMemberships = membershipInfos,
            WorkspacesRequiringAction = workspacesRequiringAction,
            CanDeleteImmediately = workspacesRequiringAction == 0
        };
    }

    public async Task<TransferAdminResponse> TransferAdminRoleAsync(int workspaceId, int fromUserId, int toUserId)
    {
        // Verify the from user is an admin
        var fromMembership = await _workspaceUserRepository.GetMembershipAsync(fromUserId, workspaceId);
        if (fromMembership == null || fromMembership.WorkspaceRole != WorkspaceRole.WorkspaceAdmin)
        {
            return new TransferAdminResponse
            {
                Success = false,
                Error = "You are not an admin of this workspace"
            };
        }

        // Verify the to user is a member of the workspace
        var toMembership = await _workspaceUserRepository.GetMembershipAsync(toUserId, workspaceId);
        if (toMembership == null)
        {
            return new TransferAdminResponse
            {
                Success = false,
                Error = "Target user is not a member of this workspace"
            };
        }

        // Promote the target user to admin
        await _workspaceUserRepository.UpdateRoleAsync(toUserId, workspaceId, WorkspaceRole.WorkspaceAdmin);

        // Demote the from user to member
        await _workspaceUserRepository.UpdateRoleAsync(fromUserId, workspaceId, WorkspaceRole.Normal);

        _logger.LogInformation("Admin role transferred in workspace {WorkspaceId} from user {FromUserId} to user {ToUserId}",
            workspaceId, fromUserId, toUserId);

        return new TransferAdminResponse { Success = true };
    }

    public async Task<DeleteUserResponse> DeleteUserAccountAsync(int userId, DeleteUserRequest request)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            return new DeleteUserResponse
            {
                Success = false,
                Error = "User not found"
            };
        }

        // Verify email confirmation
        if (!string.Equals(request.ConfirmEmail, user.Email, StringComparison.OrdinalIgnoreCase))
        {
            return new DeleteUserResponse
            {
                Success = false,
                Error = "Email confirmation does not match your account email"
            };
        }

        // Get current deletion info to check for unresolved blockers
        var deletionInfo = await GetDeletionInfoAsync(userId);
        if (deletionInfo == null)
        {
            return new DeleteUserResponse
            {
                Success = false,
                Error = "Unable to retrieve deletion info"
            };
        }

        // Process each workspace that requires action
        var actionsByWorkspace = request.WorkspaceActions.ToDictionary(a => a.WorkspaceId);

        foreach (var membership in deletionInfo.WorkspaceMemberships.Where(m => !m.CanLeave))
        {
            if (!actionsByWorkspace.TryGetValue(membership.WorkspaceId, out var action))
            {
                return new DeleteUserResponse
                {
                    Success = false,
                    Error = $"Missing action for workspace: {membership.WorkspaceName}"
                };
            }

            if (membership.BlockerReason == DeletionBlockerReason.SoleUser)
            {
                // Must delete the workspace
                if (action.Action != WorkspaceActionType.Delete)
                {
                    return new DeleteUserResponse
                    {
                        Success = false,
                        Error = $"Workspace '{membership.WorkspaceName}' must be deleted since you are the only member"
                    };
                }

                var deleteResult = await _workspaceDeletionService.SoftDeleteWorkspaceAsync(membership.WorkspaceId, userId);
                if (!deleteResult.Success)
                {
                    return new DeleteUserResponse
                    {
                        Success = false,
                        Error = $"Failed to delete workspace: {membership.WorkspaceName}"
                    };
                }

                _logger.LogInformation("Workspace {WorkspaceId} deleted as part of user {UserId} account deletion",
                    membership.WorkspaceId, userId);
            }
            else if (membership.BlockerReason == DeletionBlockerReason.SoleAdmin)
            {
                // Must transfer admin
                if (action.Action != WorkspaceActionType.Transfer || !action.TransferToUserId.HasValue)
                {
                    return new DeleteUserResponse
                    {
                        Success = false,
                        Error = $"Admin role must be transferred for workspace: {membership.WorkspaceName}"
                    };
                }

                var transferResult = await TransferAdminRoleAsync(membership.WorkspaceId, userId, action.TransferToUserId.Value);
                if (!transferResult.Success)
                {
                    return new DeleteUserResponse
                    {
                        Success = false,
                        Error = $"Failed to transfer admin for workspace '{membership.WorkspaceName}': {transferResult.Error}"
                    };
                }

                _logger.LogInformation("Admin role transferred from user {UserId} to user {ToUserId} in workspace {WorkspaceId} as part of account deletion",
                    userId, action.TransferToUserId.Value, membership.WorkspaceId);
            }
        }

        // Remove user from all remaining workspaces
        var memberships = await _workspaceUserRepository.GetByUserIdAsync(userId);
        foreach (var membership in memberships)
        {
            await _workspaceUserRepository.DeleteAsync(userId, membership.WorkspaceId);
            _logger.LogInformation("Removed user {UserId} from workspace {WorkspaceId} during account deletion",
                userId, membership.WorkspaceId);
        }

        // Delete the user account
        var deleted = await _userRepository.DeleteAsync(userId);
        if (!deleted)
        {
            return new DeleteUserResponse
            {
                Success = false,
                Error = "Failed to delete user account"
            };
        }

        _logger.LogInformation("User account {UserId} ({Email}) deleted", userId, user.Email);

        return new DeleteUserResponse { Success = true };
    }
}
