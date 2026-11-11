namespace OneBigHead.Server.Services.BulkUpdate;

public interface IBulkUpdateProperties
{
    /// <summary>Updates only properties, using the current item and verifying it still matches the job.</summary>
    Task<bool> ApplyAsync(BulkUpdateJob job, int itemId, CancellationToken cancellationToken);
}
