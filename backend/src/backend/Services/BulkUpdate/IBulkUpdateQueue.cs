namespace OneBigHead.Server.Services.BulkUpdate;

public interface IBulkUpdateQueue
{
    void Enqueue(BulkUpdateJob job);
    ValueTask<BulkUpdateJob> DequeueAsync(CancellationToken cancellationToken);
}
