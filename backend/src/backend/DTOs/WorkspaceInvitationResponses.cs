using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public sealed record WorkspaceInvitationResponse(Guid InvitationId, string Email, WorkspaceRole Role,
    DateTime CreatedAt, DateTime ExpiresAt)
{
    public static WorkspaceInvitationResponse FromInvitation(WorkspaceInvitation invitation) =>
        new(invitation.Id, invitation.Email, invitation.Role, invitation.CreatedAt, invitation.ExpiresAt);
}

/// <summary>The un-hashed token is returned only when a link is created or replaced.</summary>
public sealed record CreatedInvitationResponse(WorkspaceInvitationResponse Invitation, string Token);

public sealed record InvitationPreviewResponse(string WorkspaceName, string Email, WorkspaceRole Role, DateTime ExpiresAt);
