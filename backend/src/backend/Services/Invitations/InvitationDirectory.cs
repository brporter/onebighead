using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services.Memberships;

namespace OneBigHead.Server.Services.Invitations;

public sealed class InvitationDirectory(IDbContextFactory<AppDbContext> contexts) : IInvitationDirectory
{
    public async Task<IReadOnlyList<WorkspaceInvitationResponse>?> ReadAsync(int actorId, int workspaceId)
    {
        await using var context = await contexts.CreateDbContextAsync();
        var snapshot = await TeamAdministrator.Membership(context, actorId, workspaceId)
            .Select(member => new { Invitations = context.WorkspaceInvitations.AsNoTracking()
                .Where(invitation => invitation.WorkspaceId == workspaceId && invitation.AcceptedAt == null)
                .OrderBy(invitation => invitation.CreatedAt).ThenBy(invitation => invitation.Id).ToList() })
            .AsSingleQuery().SingleOrDefaultAsync();
        return snapshot?.Invitations.Select(WorkspaceInvitationResponse.FromInvitation).ToArray();
    }
}
