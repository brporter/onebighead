namespace OneBigHead.Server.Services.BulkUpdate;

public interface IBulkUpdateCollectionLocks
{
    void RegisterCollectionLock(int collectionId, Guid jobId);
    void ReleaseCollectionLock(int collectionId, Guid jobId);
}
