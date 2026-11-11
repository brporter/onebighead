namespace OneBigHead.Server.Services.BulkUpdate;

/// <summary>Owns queue consumption and host shutdown; job execution has its own service.</summary>
public sealed class BulkUpdateWorker(IBulkUpdateQueue queue, IBulkUpdateProcessor processor,
    ILogger<BulkUpdateWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("BulkUpdateWorker started");
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var job = await queue.DequeueAsync(stoppingToken);
                await processor.ProcessAsync(job, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Error processing bulk update job");
            }
        }
        logger.LogInformation("BulkUpdateWorker stopped");
    }
}
