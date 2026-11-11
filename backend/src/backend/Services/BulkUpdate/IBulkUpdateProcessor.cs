namespace OneBigHead.Server.Services.BulkUpdate;

public interface IBulkUpdateProcessor
{
    Task ProcessAsync(BulkUpdateJob job, CancellationToken cancellationToken);
}
