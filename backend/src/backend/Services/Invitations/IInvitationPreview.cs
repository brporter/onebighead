using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Invitations;

public interface IInvitationPreview
{
    Task<InvitationPreviewResponse?> ReadAsync(InvitationAccessRequest request, CancellationToken cancellationToken = default);
}
