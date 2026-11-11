namespace OneBigHead.Server.Services.Invitations;

public interface IInvitationCancellation
{
    Task<InvitationCancellationStatus> CancelAsync(int actorId, int workspaceId, Guid invitationId);
}

public enum InvitationCancellationStatus { Cancelled, Forbidden, NotFound, Conflict }
