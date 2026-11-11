using System.Data;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Invitations;

public sealed class InvitationAcceptance(IDbContextFactory<AppDbContext> contexts, TimeProvider time) : IInvitationAcceptance
{
    public async Task<InvitationAcceptanceResult> AcceptAsync(int userId, InvitationAccessRequest request, CancellationToken cancellationToken = default)
    {
        var hash = InvitationTokens.ReadHash(request);
        if (hash is null) return new(InvitationAcceptanceStatus.Invalid);
        await using var context = await contexts.CreateDbContextAsync(cancellationToken);
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        try
        {
            var user = await context.Users.Include(user => user.WorkspaceMemberships).ThenInclude(member => member.Workspace)
                .AsSingleQuery().SingleOrDefaultAsync(user => user.Id == userId && !user.IsDeleted, cancellationToken);
            if (user is null) return new(InvitationAcceptanceStatus.Unauthenticated);
            var invitation = await context.WorkspaceInvitations.Include(invitation => invitation.Workspace)
                .SingleOrDefaultAsync(invitation => invitation.Id == request.InvitationId && invitation.TokenHash == hash && !invitation.Workspace.IsDeleted, cancellationToken);
            if (invitation is null) return new(InvitationAcceptanceStatus.Invalid);
            var membership = user.WorkspaceMemberships.SingleOrDefault(member => member.WorkspaceId == invitation.WorkspaceId);
            // A retry can acknowledge the same completed grant, but cannot restore removed access or overwrite a later role.
            if (invitation.AcceptedAt is not null)
                return invitation.AcceptedByUserId == userId && membership is not null
                    ? new(InvitationAcceptanceStatus.Joined, CurrentUserSession.FromUser(user))
                    : new(InvitationAcceptanceStatus.Invalid);
            var now = time.GetUtcNow().UtcDateTime;
            if (invitation.ExpiresAt <= now) return new(InvitationAcceptanceStatus.Invalid);
            var newMembership = membership is null;
            if (newMembership)
                context.WorkspaceUsers.Add(new WorkspaceUser { User = user, Workspace = invitation.Workspace,
                    WorkspaceRole = invitation.Role, CreatedAt = now });
            user.ActiveWorkspaceId = invitation.WorkspaceId;
            invitation.AcceptedAt = now;
            invitation.AcceptedByUserId = userId;
            await context.SaveChangesAsync(cancellationToken);
            if (newMembership) await TokenRevocationWrite.UpsertAsync(context, userId, TokenRevocationTimestamp.From(time.GetUtcNow()), cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new(InvitationAcceptanceStatus.Joined, CurrentUserSession.FromUser(user));
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception))
        {
            return new(InvitationAcceptanceStatus.Conflict);
        }
    }
}
