using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Workspaces;

public sealed class WorkspaceRestorationService(
    IDbContextFactory<AppDbContext> contextFactory,
    ILogger<WorkspaceRestorationService> logger) : IWorkspaceRestorationService
{
    public Task<WorkspaceRestorationResult> RestoreAsync(int userId, int workspaceId, CancellationToken cancellationToken = default) =>
        RestoreSelectionAsync(userId, [workspaceId], activateFirst: false, cancellationToken);

    public Task<WorkspaceRestorationResult> RestoreAndActivateAsync(int userId, IReadOnlyCollection<int> workspaceIds, CancellationToken cancellationToken = default) =>
        RestoreSelectionAsync(userId, workspaceIds, activateFirst: true, cancellationToken);

    private async Task<WorkspaceRestorationResult> RestoreSelectionAsync(
        int userId, IReadOnlyCollection<int> workspaceIds, bool activateFirst, CancellationToken cancellationToken)
    {
        if (workspaceIds.Count == 0)
            throw new ArgumentException("At least one workspace ID is required", nameof(workspaceIds));

        // Preserve selection order while restoring each workspace at most once.
        var ids = workspaceIds.Distinct().ToArray();
        await using var context = await contextFactory.CreateDbContextAsync(cancellationToken);
        var user = await context.Users.SingleOrDefaultAsync(u => u.Id == userId && !u.IsDeleted, cancellationToken);
        if (user is null)
            return new(false, [], null);

        var memberships = await context.WorkspaceUsers.Include(m => m.Workspace)
            .Where(m => m.UserId == userId && ids.Contains(m.WorkspaceId))
            .ToDictionaryAsync(m => m.WorkspaceId, cancellationToken);

        // Validate the entire batch before changing any tracked entity.
        if (memberships.Count != ids.Length || memberships.Values.Any(m => m.WorkspaceRole != WorkspaceRole.WorkspaceAdmin))
            return new(false, [], null);

        var restored = ids.Select(id => memberships[id].Workspace).Where(w => w.IsDeleted).ToList();
        foreach (var workspace in restored)
        {
            workspace.IsDeleted = false;
            workspace.DeletedAt = null;
            workspace.DeletedByUserId = null;
        }

        User? activeUser = null;
        if (activateFirst && restored.Count > 0)
        {
            user.ActiveWorkspaceId = restored[0].Id;
            activeUser = user;
        }

        // EF commits every workspace and the active-workspace change in one transaction.
        // No repository call opens a second context or commits an intermediate state.
        await context.SaveChangesAsync(cancellationToken);
        foreach (var workspace in restored)
            logger.LogInformation("User {UserId} restored workspace {WorkspaceId} ({WorkspaceName})", userId, workspace.Id, workspace.Name);

        return new(true, restored, activeUser);
    }
}
