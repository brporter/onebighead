using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Administration;

namespace OneBigHead.Server.DTOs;

/// <summary>Current account and membership state, including accounts without a workspace.</summary>
public sealed class CurrentUserResponse
{
    public required int UserId { get; init; }
    public required string Email { get; init; }
    public WorkspaceMembershipResponse? ActiveWorkspace { get; init; }
    public required IReadOnlyList<WorkspaceMembershipResponse> Workspaces { get; init; }
    public required bool HasAcceptedTerms { get; init; }
    public required bool IsSystemAdministrator { get; init; }
    public int? WorkspaceId => ActiveWorkspace?.WorkspaceId;
    public string WorkspaceName => ActiveWorkspace?.WorkspaceName ?? string.Empty;
    public bool HasCompletedWelcome => ActiveWorkspace?.HasCompletedWelcome ?? false;
    public WorkspaceRole WorkspaceRole => ActiveWorkspace?.WorkspaceRole ?? WorkspaceRole.Normal;
    public bool IsWorkspaceAdmin => WorkspaceRole == WorkspaceRole.WorkspaceAdmin;

    public static CurrentUserResponse FromUser(User user)
    {
        var memberships = user.WorkspaceMemberships
            .Where(m => !m.Workspace.IsDeleted)
            .OrderBy(m => m.WorkspaceId)
            .Select(m => new WorkspaceMembershipResponse
            {
                WorkspaceId = m.WorkspaceId,
                WorkspaceName = m.Workspace.Name,
                WorkspaceRole = m.WorkspaceRole,
                HasCompletedWelcome = m.Workspace.HasCompletedWelcome,
                Slug = m.Workspace.Slug
            }).ToList();
        return new()
        {
            UserId = user.Id,
            Email = user.Email,
            ActiveWorkspace = memberships.SingleOrDefault(m => m.WorkspaceId == user.ActiveWorkspaceId),
            Workspaces = memberships,
            HasAcceptedTerms = user.HasAcceptedTerms,
            IsSystemAdministrator = AdministratorAccessPolicy.IsAllowed(user)
        };
    }
}
