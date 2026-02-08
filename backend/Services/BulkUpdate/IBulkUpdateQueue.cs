namespace OneBigHead.Server.Services.BulkUpdate;

public interface IBulkUpdateQueue
{
    void Enqueue(BulkUpdateJob job);
    ValueTask<BulkUpdateJob> DequeueAsync(CancellationToken cancellationToken);
    BulkUpdateJob? GetJob(Guid jobId, int workspaceId);
    BulkUpdateJob? GetActiveJobForCollection(int collectionId, int workspaceId);
    void RegisterCollectionLock(int collectionId, Guid jobId);
    void ReleaseCollectionLock(int collectionId);
}
