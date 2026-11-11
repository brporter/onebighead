using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services.BulkUpdate;

public sealed class BulkUpdateProcessor(IBulkUpdateTargets targets, IBulkUpdateProperties properties,
    IBulkUpdateCollectionLocks collections, ILogger<BulkUpdateProcessor> logger) : IBulkUpdateProcessor
{
    public async Task ProcessAsync(BulkUpdateJob job, CancellationToken cancellationToken)
    {
        using var activity = DiagnosticsConfig.AppActivitySource.StartActivity("BulkUpdate.ProcessJob");
        activity?.SetTag("job.id", job.JobId.ToString());
        activity?.SetTag("job.workspaceId", job.WorkspaceId);
        var lockedCollections = new List<int>();
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            job.Status = BulkUpdateJobStatus.Running;
            var items = await targets.GetAsync(job.Target, job.WorkspaceId, cancellationToken);
            job.TotalItems = items.Count;
            foreach (var collectionId in items.Select(item => item.CollectionId).Distinct())
            {
                collections.RegisterCollectionLock(collectionId, job.JobId);
                lockedCollections.Add(collectionId);
            }

            foreach (var item in items)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    if (await properties.ApplyAsync(job, item.Id, cancellationToken)) job.ProcessedItems++;
                    else job.FailedItems++;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (UnauthorizedAccessException)
                {
                    // Losing access stops the entire job, rather than trying every remaining item.
                    throw;
                }
                catch (Exception exception)
                {
                    logger.LogWarning(exception, "Failed to update item {ItemId} in bulk update job {JobId}", item.Id, job.JobId);
                    job.FailedItems++;
                }
            }
            job.Status = BulkUpdateJobStatus.Completed;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            job.Status = BulkUpdateJobStatus.Cancelled;
            job.ErrorMessage = "The update was interrupted. Some items may already have been updated.";
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Bulk update job {JobId} failed", job.JobId);
            job.Status = BulkUpdateJobStatus.Failed;
            job.ErrorMessage = "Unable to finish the item update. Some items may already have been updated.";
            activity?.AddException(exception);
        }
        finally
        {
            job.CompletedAt = DateTime.UtcNow;
            foreach (var collectionId in lockedCollections)
                collections.ReleaseCollectionLock(collectionId, job.JobId);
            activity?.SetTag("job.totalItems", job.TotalItems);
            activity?.SetTag("job.processedItems", job.ProcessedItems);
            activity?.SetTag("job.failedItems", job.FailedItems);
        }
    }
}
