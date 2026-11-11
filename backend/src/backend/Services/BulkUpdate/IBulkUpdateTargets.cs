namespace OneBigHead.Server.Services.BulkUpdate;

public sealed record BulkUpdateItem(int Id, int CollectionId);

public interface IBulkUpdateTargets
{
    Task<int> CountAsync(BulkUpdateTarget target, int workspaceId, CancellationToken cancellationToken);
    Task<IReadOnlyList<BulkUpdateItem>> GetAsync(BulkUpdateTarget target, int workspaceId, CancellationToken cancellationToken);
}
