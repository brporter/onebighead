using OneBigHead.Server.Authentication;
using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Invitations;

public interface IInvitationAcceptance
{
    Task<InvitationAcceptanceResult> AcceptAsync(int userId, InvitationAccessRequest request, CancellationToken cancellationToken = default);
}

public enum InvitationAcceptanceStatus { Joined, Invalid, Unauthenticated, Conflict }
public sealed record InvitationAcceptanceResult(InvitationAcceptanceStatus Status, CurrentUserSession? Session = null);
