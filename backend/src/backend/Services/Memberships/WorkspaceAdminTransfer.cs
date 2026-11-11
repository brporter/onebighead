using System.Data;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Memberships;

public sealed class WorkspaceAdminTransfer(
    IDbContextFactory<AppDbContext> contextFactory,
    TimeProvider time,
    ILogger<WorkspaceAdminTransfer> logger) : IWorkspaceAdminTransfer
{
    public async Task<WorkspaceAdminTransferResult> TransferAsync(int userId, int workspaceId, int newAdminUserId)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        try
        {
            var user = await MembershipSnapshot.LoadActiveUserAsync(context, userId);
            var membership = user?.WorkspaceMemberships.SingleOrDefault(m => m.WorkspaceId == workspaceId && !m.Workspace.IsDeleted);
            if (membership is null) return new(WorkspaceAdminTransferStatus.NotFound, "Workspace not found");
            if (membership.WorkspaceRole != WorkspaceRole.WorkspaceAdmin) return new(WorkspaceAdminTransferStatus.Forbidden);
            if (userId == newAdminUserId) return new(WorkspaceAdminTransferStatus.Invalid, "Choose another member to receive the admin role");

            var recipient = await context.WorkspaceUsers.Include(m => m.User)
                .SingleOrDefaultAsync(m => m.WorkspaceId == workspaceId && m.UserId == newAdminUserId && !m.User.IsDeleted);
            if (recipient is null) return new(WorkspaceAdminTransferStatus.Invalid, "Target user is not an active member of this workspace");

            membership.WorkspaceRole = WorkspaceRole.Normal;
            recipient.WorkspaceRole = WorkspaceRole.WorkspaceAdmin;
            await context.SaveChangesAsync();

            // These writes use the same context/transaction as both role changes.
            // A stable lock order also avoids reverse transfers deadlocking here.
            var revokedAt = TokenRevocationTimestamp.From(time.GetUtcNow());
            foreach (var affectedId in new[] { userId, newAdminUserId }.Order())
                await TokenRevocationWrite.UpsertAsync(context, affectedId, revokedAt);
            await transaction.CommitAsync();

            logger.LogInformation("User {UserId} transferred admin role to user {NewAdminUserId} in workspace {WorkspaceId}",
                userId, newAdminUserId, workspaceId);

            // Preserve the role of the actual active workspace, which may differ
            // from the workspace whose administrator was transferred.
            return new(WorkspaceAdminTransferStatus.Transferred, Session: CurrentUserSession.FromUser(user!));
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception))
        {
            return new(WorkspaceAdminTransferStatus.Conflict, "Workspace membership changed. Reload members and review the transfer");
        }
    }
}
