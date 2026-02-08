using OneBigHead.Server.Data;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services.BulkUpdate;

public class BulkUpdateWorker : BackgroundService
{
    private readonly IBulkUpdateQueue _queue;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<BulkUpdateWorker> _logger;

    public BulkUpdateWorker(
        IBulkUpdateQueue queue,
        IServiceScopeFactory scopeFactory,
        ILogger<BulkUpdateWorker> logger)
    {
        _queue = queue;
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("BulkUpdateWorker started");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var job = await _queue.DequeueAsync(stoppingToken);
                await ProcessJobAsync(job, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing bulk update job");
            }
        }

        _logger.LogInformation("BulkUpdateWorker stopped");
    }

    private async Task ProcessJobAsync(BulkUpdateJob job, CancellationToken stoppingToken)
    {
        using var activity = DiagnosticsConfig.AppActivitySource.StartActivity("BulkUpdate.ProcessJob");
        activity?.SetTag("job.id", job.JobId.ToString());
        activity?.SetTag("job.scope", job.Scope.ToString());
        activity?.SetTag("job.workspaceId", job.WorkspaceId);

        using var scope = _scopeFactory.CreateScope();
        var itemRepository = scope.ServiceProvider.GetRequiredService<IItemRepository>();
        var diffService = scope.ServiceProvider.GetRequiredService<IPropertyDiffService>();

        int? collectionId = null;

        try
        {
            job.Status = BulkUpdateJobStatus.Running;

            // Fetch target items based on scope
            var items = await GetTargetItemsAsync(job, itemRepository);
            var itemList = items.ToList();

            // Exclude the source item if specified
            if (job.ExcludeItemId.HasValue)
            {
                itemList.RemoveAll(i => i.Id == job.ExcludeItemId.Value);
            }

            job.TotalItems = itemList.Count;

            // Resolve collection ID for locking
            collectionId = job.CollectionId ?? itemList.FirstOrDefault()?.CollectionId;
            if (collectionId.HasValue)
            {
                _queue.RegisterCollectionLock(collectionId.Value, job.JobId);
            }

            // Process each item
            foreach (var item in itemList)
            {
                if (stoppingToken.IsCancellationRequested)
                {
                    break;
                }

                try
                {
                    var updatedProperties = diffService.ApplyDiff(
                        item.Properties, job.Diff, job.NewPropertyOrder);

                    item.Properties = updatedProperties;
                    await itemRepository.UpdateAsync(item.Id!.Value, item, job.WorkspaceId);

                    job.ProcessedItems++;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to update item {ItemId} in bulk update job {JobId}",
                        item.Id, job.JobId);
                    job.FailedItems++;
                }
            }

            job.Status = BulkUpdateJobStatus.Completed;
            activity?.SetTag("job.totalItems", job.TotalItems);
            activity?.SetTag("job.processedItems", job.ProcessedItems);
            activity?.SetTag("job.failedItems", job.FailedItems);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Bulk update job {JobId} failed", job.JobId);
            job.Status = BulkUpdateJobStatus.Failed;
            job.ErrorMessage = ex.Message;
            activity?.AddException(ex);
        }
        finally
        {
            job.CompletedAt = DateTime.UtcNow;
            if (collectionId.HasValue)
            {
                _queue.ReleaseCollectionLock(collectionId.Value);
            }
        }
    }

    private static async Task<IEnumerable<Models.Item>> GetTargetItemsAsync(
        BulkUpdateJob job, IItemRepository itemRepository)
    {
        return job.Scope switch
        {
            BulkUpdateScope.Template when job.TemplateKey.HasValue =>
                await itemRepository.GetByTemplateKeyAsync(job.TemplateKey.Value, job.WorkspaceId),
            BulkUpdateScope.Category when job.CategoryId.HasValue =>
                await itemRepository.GetByCategoryIdsAsync(new[] { job.CategoryId.Value }, job.WorkspaceId),
            BulkUpdateScope.Collection when job.CollectionId.HasValue =>
                await itemRepository.GetByCollectionIdAsync(job.CollectionId.Value, job.WorkspaceId),
            _ => Enumerable.Empty<Models.Item>()
        };
    }
}
