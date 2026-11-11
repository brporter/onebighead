using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Accounts;

internal static class AccountDeletionPolicy
{
    public static UserDeletionInfoResponse Describe(User user)
    {
        var memberships = user.WorkspaceMemberships.Where(m => !m.Workspace.IsDeleted)
            .OrderBy(m => m.WorkspaceId).Select(DescribeMembership).ToList();
        var requiringAction = memberships.Count(m => !m.CanLeave);
        return new()
        {
            UserId = user.Id, Email = user.Email, WorkspaceMemberships = memberships,
            WorkspacesRequiringAction = requiringAction, CanDeleteImmediately = requiringAction == 0
        };
    }

    private static WorkspaceMembershipDeletionInfo DescribeMembership(WorkspaceUser membership)
    {
        var members = membership.Workspace.WorkspaceUsers;
        var others = members.Where(m => m.UserId != membership.UserId).Where(m => !m.User.IsDeleted).ToList();
        var soleUser = members.Count == 1;
        var soleAdmin = membership.WorkspaceRole == WorkspaceRole.WorkspaceAdmin && !soleUser &&
            !others.Any(m => m.WorkspaceRole == WorkspaceRole.WorkspaceAdmin);
        var reason = soleUser ? DeletionBlockerReason.SoleUser :
            soleAdmin ? DeletionBlockerReason.SoleAdmin : DeletionBlockerReason.None;
        return new()
        {
            WorkspaceId = membership.WorkspaceId, WorkspaceName = membership.Workspace.Name,
            Role = membership.WorkspaceRole, UserCount = members.Count, IsOnlyUser = soleUser,
            IsOnlyAdmin = soleAdmin, BlockerReason = reason, CanLeave = reason == DeletionBlockerReason.None,
            OtherUsers = soleAdmin ? others.OrderBy(m => m.User.Email, StringComparer.OrdinalIgnoreCase).ThenBy(m => m.UserId)
                .Select(m => new UserBasicInfo { UserId = m.UserId, Email = m.User.Email }).ToList() : []
        };
    }

    // Validate the entire request before applying any part of it. A stale or extra
    // action is rejected instead of silently changing the user's confirmed plan.
    public static string? Validate(UserDeletionInfoResponse info, DeleteUserRequest request)
    {
        if (!string.Equals(request.ConfirmEmail, info.Email, StringComparison.OrdinalIgnoreCase))
            return "Email confirmation does not match your account email";
        var actions = new Dictionary<int, WorkspaceActionRequest>();
        foreach (var action in request.WorkspaceActions)
        {
            if (action is null) return "Choose a valid action for each workspace";
            if (!actions.TryAdd(action.WorkspaceId, action)) return "Choose only one action for each workspace";
        }

        var blockers = info.WorkspaceMemberships.Where(m => !m.CanLeave).ToList();
        var requiredIds = blockers.Select(m => m.WorkspaceId).ToHashSet();
        if (actions.Keys.Any(id => !requiredIds.Contains(id)))
            return "Workspace membership changed. Reload account deletion information and review your choices";

        foreach (var blocker in blockers)
        {
            if (!actions.TryGetValue(blocker.WorkspaceId, out var action))
                return $"Missing action for workspace: {blocker.WorkspaceName}";
            if (blocker.BlockerReason == DeletionBlockerReason.SoleUser)
            {
                if (action.Action != WorkspaceActionType.Delete || action.TransferToUserId.HasValue)
                    return $"Workspace '{blocker.WorkspaceName}' must be deleted since you are the only member";
            }
            else
            {
                if (action.Action != WorkspaceActionType.Transfer || !action.TransferToUserId.HasValue)
                    return $"Admin role must be transferred for workspace: {blocker.WorkspaceName}";
                if (!blocker.OtherUsers.Any(u => u.UserId == action.TransferToUserId))
                    return $"Choose an active member of workspace '{blocker.WorkspaceName}' to receive the admin role";
            }
        }
        return null;
    }
}
