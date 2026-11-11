using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Memberships;

public interface ITeamInvitations
{
    Task<TeamInvitationResult> InviteAsync(int actorId, int workspaceId, InviteUserRequest request);
}

public enum TeamInvitationStatus { Created, Forbidden, Invalid, Conflict }

public sealed record TeamInvitationResult(TeamInvitationStatus Status, CreatedInvitationResponse? Invitation = null, string? Error = null);
