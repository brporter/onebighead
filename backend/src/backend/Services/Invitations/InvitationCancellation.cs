using System.Data;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Services.Memberships;

namespace OneBigHead.Server.Services.Invitations;

public sealed class InvitationCancellation(IDbContextFactory<AppDbContext> contexts) : IInvitationCancellation
{
    public async Task<InvitationCancellationStatus> CancelAsync(int actorId, int workspaceId, Guid invitationId)
    {
        await using var context = await contexts.CreateDbContextAsync();
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        try
        {
            if (!await TeamAdministrator.Membership(context, actorId, workspaceId).AnyAsync()) return InvitationCancellationStatus.Forbidden;
            var count = await context.WorkspaceInvitations.Where(invitation => invitation.Id == invitationId &&
                invitation.WorkspaceId == workspaceId && invitation.AcceptedAt == null).ExecuteDeleteAsync();
            await transaction.CommitAsync();
            return count == 0 ? InvitationCancellationStatus.NotFound : InvitationCancellationStatus.Cancelled;
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception))
        {
            return InvitationCancellationStatus.Conflict;
        }
    }
}
