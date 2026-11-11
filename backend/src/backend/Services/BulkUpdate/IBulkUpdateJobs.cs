namespace OneBigHead.Server.Services.BulkUpdate;

public interface IBulkUpdateJobs
{
    BulkUpdateJob? GetJob(Guid jobId, int workspaceId);
    BulkUpdateJob? GetActiveJobForCollection(int collectionId, int workspaceId);
}
