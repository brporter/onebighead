using System.Data;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;

namespace OneBigHead.Server.Services.BulkUpdate;

public sealed class BulkUpdateItemStore(IDbContextFactory<AppDbContext> contexts, IPropertyDiffService differences)
    : IBulkUpdateTargets, IBulkUpdateProperties
{
    public async Task<int> CountAsync(BulkUpdateTarget target, int workspaceId, CancellationToken cancellationToken)
    {
        await using var context = await contexts.CreateDbContextAsync(cancellationToken);
        return await target.Select(context.Items, workspaceId).CountAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<BulkUpdateItem>> GetAsync(BulkUpdateTarget target, int workspaceId,
        CancellationToken cancellationToken)
    {
        await using var context = await contexts.CreateDbContextAsync(cancellationToken);
        return await target.Select(context.Items.AsNoTracking(), workspaceId).OrderBy(item => item.Id)
            .Select(item => new BulkUpdateItem(item.Id!.Value, item.CollectionId)).ToListAsync(cancellationToken);
    }

    public async Task<bool> ApplyAsync(BulkUpdateJob job, int itemId, CancellationToken cancellationToken)
    {
        await using var context = await contexts.CreateDbContextAsync(cancellationToken);
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        var authorized = await context.WorkspaceUsers.AnyAsync(member => member.UserId == job.RequestedByUserId
            && member.WorkspaceId == job.WorkspaceId && !member.User!.IsDeleted && !member.Workspace!.IsDeleted, cancellationToken);
        if (!authorized) throw new UnauthorizedAccessException("Workspace access is no longer available.");
        var item = await job.Target.Select(context.Items, job.WorkspaceId)
            .SingleOrDefaultAsync(value => value.Id == itemId, cancellationToken);
        if (item is null) return false;

        item.Properties = differences.ApplyDiff(item.Properties, job.Diff, job.NewPropertyOrder);
        await context.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return true;
    }
}
