using System.Data;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Memberships;

public sealed class WorkspaceLeave(
    IDbContextFactory<AppDbContext> contextFactory,
    TimeProvider time,
    ILogger<WorkspaceLeave> logger) : IWorkspaceLeave
{
    public async Task<WorkspaceLeaveResult> LeaveAsync(int userId, int workspaceId)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        try
        {
            var user = await MembershipSnapshot.LoadActiveUserAsync(context, userId);
            var membership = user?.WorkspaceMemberships.SingleOrDefault(m => m.WorkspaceId == workspaceId && !m.Workspace.IsDeleted);
            if (membership is null) return new(WorkspaceLeaveStatus.NotFound, "You are not a member of this workspace");

            var remaining = user!.WorkspaceMemberships.Where(m => m.WorkspaceId != workspaceId && !m.Workspace.IsDeleted)
                .OrderBy(m => m.WorkspaceId).ToList();
            if (remaining.Count == 0) return new(WorkspaceLeaveStatus.Invalid, "Cannot leave your only active workspace");
            if (membership.WorkspaceRole == WorkspaceRole.WorkspaceAdmin && !await context.WorkspaceUsers.AnyAsync(m =>
                m.WorkspaceId == workspaceId && m.UserId != userId && m.WorkspaceRole == WorkspaceRole.WorkspaceAdmin && !m.User.IsDeleted))
                return new(WorkspaceLeaveStatus.Invalid, "Cannot leave: you are the only admin in this workspace. Promote another user to admin first.");

            context.WorkspaceUsers.Remove(membership);
            user.WorkspaceMemberships.Remove(membership);
            // Retain a valid active membership; otherwise choose deterministically
            // from active workspaces instead of selecting a deleted workspace.
            user.ActiveWorkspaceId = remaining.FirstOrDefault(m => m.WorkspaceId == user.ActiveWorkspaceId)?.WorkspaceId ?? remaining[0].WorkspaceId;
            await context.SaveChangesAsync();
            await TokenRevocationWrite.UpsertAsync(context, userId, TokenRevocationTimestamp.From(time.GetUtcNow()));
            await transaction.CommitAsync();

            logger.LogInformation("User {UserId} left workspace {WorkspaceId}", userId, workspaceId);
            return new(WorkspaceLeaveStatus.Left, Session: CurrentUserSession.FromUser(user));
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception))
        {
            return new(WorkspaceLeaveStatus.Conflict, "Workspace membership changed. Reload your workspaces before leaving");
        }
    }
}
