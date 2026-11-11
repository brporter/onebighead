using System.Data;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;

namespace OneBigHead.Server.Services.Memberships;

public sealed class WorkspaceSwitch(IDbContextFactory<AppDbContext> contextFactory, ILogger<WorkspaceSwitch> logger) : IWorkspaceSwitch
{
    public async Task<WorkspaceSwitchResult> SwitchAsync(int userId, int workspaceId)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        try
        {
            var user = await MembershipSnapshot.LoadActiveUserAsync(context, userId);
            var membership = user?.WorkspaceMemberships.SingleOrDefault(m => m.WorkspaceId == workspaceId && !m.Workspace.IsDeleted);
            if (membership is null) return new(WorkspaceSwitchStatus.Forbidden);

            user!.ActiveWorkspaceId = workspaceId;
            if (context.ChangeTracker.HasChanges()) await context.SaveChangesAsync();
            await transaction.CommitAsync();
            logger.LogInformation("User {UserId} switched to workspace {WorkspaceId}", userId, workspaceId);
            // Build the cookie from the same membership snapshot that authorized
            // the write, rather than separately reading potentially stale roles.
            return new(WorkspaceSwitchStatus.Switched, Session: CurrentUserSession.FromUser(user));
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception))
        {
            return new(WorkspaceSwitchStatus.Conflict, "Workspace membership changed. Reload your workspaces before switching");
        }
    }
}
