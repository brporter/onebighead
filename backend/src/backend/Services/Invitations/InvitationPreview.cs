using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Invitations;

public sealed class InvitationPreview(IDbContextFactory<AppDbContext> contexts, TimeProvider time) : IInvitationPreview
{
    public async Task<InvitationPreviewResponse?> ReadAsync(InvitationAccessRequest request, CancellationToken cancellationToken = default)
    {
        var hash = InvitationTokens.ReadHash(request);
        if (hash is null) return null;
        await using var context = await contexts.CreateDbContextAsync(cancellationToken);
        var now = time.GetUtcNow().UtcDateTime;
        return await context.WorkspaceInvitations.Where(invitation => invitation.Id == request.InvitationId &&
            invitation.TokenHash == hash && invitation.AcceptedAt == null && invitation.ExpiresAt > now && !invitation.Workspace.IsDeleted)
            .Select(invitation => new InvitationPreviewResponse(invitation.Workspace.Name, invitation.Email, invitation.Role, invitation.ExpiresAt))
            .SingleOrDefaultAsync(cancellationToken);
    }
}
