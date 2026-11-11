using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Invitations;

public interface IInvitationDirectory
{
    Task<IReadOnlyList<WorkspaceInvitationResponse>?> ReadAsync(int actorId, int workspaceId);
}
