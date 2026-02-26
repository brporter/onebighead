using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;
using Microsoft.Extensions.Options;

namespace OneBigHead.Server.Services.Matching;

public class MatchingWorker : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<MatchingWorker> _logger;
    private readonly LlmSettings _settings;

    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(30);
    private const int BatchSize = 5;
    private const int MaxRetries = 3;

    public MatchingWorker(
        IServiceScopeFactory scopeFactory,
        IOptions<LlmSettings> settings,
        ILogger<MatchingWorker> logger)
    {
        _scopeFactory = scopeFactory;
        _settings = settings.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("MatchingWorker started (enabled: {Enabled})", _settings.Enabled);

        if (!_settings.Enabled)
        {
            _logger.LogInformation("MatchingWorker disabled via configuration, exiting");
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ProcessBatchAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in MatchingWorker poll cycle");
            }

            await Task.Delay(PollInterval, stoppingToken);
        }

        _logger.LogInformation("MatchingWorker stopped");
    }

    private async Task ProcessBatchAsync(CancellationToken stoppingToken)
    {
        using var scope = _scopeFactory.CreateScope();
        var matchRepository = scope.ServiceProvider.GetRequiredService<IMatchRepository>();
        var itemRepository = scope.ServiceProvider.GetRequiredService<IItemRepository>();
        var embeddingService = scope.ServiceProvider.GetRequiredService<IEmbeddingService>();
        var embeddingRepository = scope.ServiceProvider.GetRequiredService<IItemEmbeddingRepository>();
        var matchingService = scope.ServiceProvider.GetRequiredService<IMatchingService>();
        var llmService = scope.ServiceProvider.GetRequiredService<ILlmService>();

        var entries = await matchRepository.DequeueAsync(BatchSize);
        if (entries.Count == 0)
            return;

        _logger.LogInformation("Processing {Count} match queue entries", entries.Count);

        foreach (var entry in entries)
        {
            if (stoppingToken.IsCancellationRequested)
                break;

            await ProcessEntryAsync(entry, itemRepository, embeddingService,
                embeddingRepository, matchRepository, matchingService, llmService, stoppingToken);
        }
    }

    private async Task ProcessEntryAsync(
        MatchQueueEntry entry,
        IItemRepository itemRepository,
        IEmbeddingService embeddingService,
        IItemEmbeddingRepository embeddingRepository,
        IMatchRepository matchRepository,
        IMatchingService matchingService,
        ILlmService llmService,
        CancellationToken stoppingToken)
    {
        using var activity = DiagnosticsConfig.AppActivitySource.StartActivity("MatchingWorker.ProcessEntry");
        activity?.SetTag("entry.id", entry.Id);
        activity?.SetTag("entry.itemId", entry.ItemId);
        activity?.SetTag("entry.reason", entry.Reason.ToString());

        try
        {
            var item = await itemRepository.GetByIdCrossWorkspaceAsync(entry.ItemId);

            if (item == null)
            {
                // Item was deleted - remove existing matches
                await matchingService.RemoveMatchesForItemAsync(entry.ItemId);
                await MarkCompleted(matchRepository, entry);
                return;
            }

            if (item.UserFlag == UserFlag.Have)
            {
                // User changed flag to Have - remove existing matches
                await matchingService.RemoveMatchesForItemAsync(entry.ItemId);
                await MarkCompleted(matchRepository, entry);
                return;
            }

            if (item.UserFlag == UserFlag.Want)
            {
                await ProcessWantItemAsync(item, embeddingService, embeddingRepository,
                    matchRepository, matchingService, llmService, stoppingToken);
            }
            else if (item.UserFlag == UserFlag.TradeOrSell)
            {
                await ProcessTradeOrSellItemAsync(item, embeddingService, embeddingRepository,
                    matchingService);
            }

            await MarkCompleted(matchRepository, entry);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to process match queue entry {EntryId} for item {ItemId}",
                entry.Id, entry.ItemId);
            activity?.AddException(ex);

            entry.RetryCount++;
            if (entry.RetryCount >= MaxRetries)
            {
                entry.Status = MatchQueueStatus.Failed;
                entry.ErrorMessage = ex.Message;
                entry.ProcessedAt = DateTime.UtcNow;
            }
            else
            {
                entry.Status = MatchQueueStatus.Pending; // Re-enqueue for retry
            }

            await matchRepository.UpdateQueueEntryAsync(entry);
        }
    }

    private async Task ProcessWantItemAsync(
        Item item,
        IEmbeddingService embeddingService,
        IItemEmbeddingRepository embeddingRepository,
        IMatchRepository matchRepository,
        IMatchingService matchingService,
        ILlmService llmService,
        CancellationToken stoppingToken)
    {
        // Generate/update embedding
        var contentHash = embeddingService.ComputeContentHash(item);
        var existingEmbedding = await embeddingRepository.GetByItemIdAsync(item.Id!.Value);

        if (existingEmbedding == null || existingEmbedding.ContentHash != contentHash)
        {
            var vector = await embeddingService.GenerateEmbeddingAsync(item, stoppingToken);
            await embeddingRepository.UpsertAsync(new ItemEmbedding
            {
                ItemId = item.Id!.Value,
                WorkspaceId = item.WorkspaceId,
                Vector = vector,
                ContentHash = contentHash
            });
        }

        // Find candidates
        var candidates = await matchingService.FindCandidatesAsync(item);
        if (candidates.Count == 0)
            return;

        // Send to LLM for evaluation
        var candidateItems = candidates.Select(c => c.Item).ToList();
        var llmResults = await llmService.EvaluateMatchesAsync(item, candidateItems, stoppingToken);

        // Create/update matches for results above threshold
        foreach (var result in llmResults)
        {
            if (result.ConfidenceScore < _settings.ConfidenceThreshold)
                continue;

            var candidateItem = candidateItems.FirstOrDefault(c => c.Id == result.ItemId);
            if (candidateItem == null)
                continue;

            var existingMatch = await matchRepository.GetByItemPairAsync(item.Id!.Value, result.ItemId);
            if (existingMatch != null)
            {
                existingMatch.ConfidenceScore = result.ConfidenceScore;
                existingMatch.MatchReason = result.Reason;
                await matchRepository.UpdateAsync(existingMatch);
            }
            else
            {
                await matchRepository.CreateAsync(new ItemMatch
                {
                    WantItemId = item.Id!.Value,
                    WantWorkspaceId = item.WorkspaceId,
                    TradeItemId = result.ItemId,
                    TradeWorkspaceId = candidateItem.WorkspaceId,
                    ConfidenceScore = result.ConfidenceScore,
                    MatchReason = result.Reason
                });
            }
        }
    }

    private async Task ProcessTradeOrSellItemAsync(
        Item item,
        IEmbeddingService embeddingService,
        IItemEmbeddingRepository embeddingRepository,
        IMatchingService matchingService)
    {
        // Generate/update embedding so future Want evaluations can find this item
        var contentHash = embeddingService.ComputeContentHash(item);
        var existingEmbedding = await embeddingRepository.GetByItemIdAsync(item.Id!.Value);

        if (existingEmbedding == null || existingEmbedding.ContentHash != contentHash)
        {
            var vector = await embeddingService.GenerateEmbeddingAsync(item);
            await embeddingRepository.UpsertAsync(new ItemEmbedding
            {
                ItemId = item.Id!.Value,
                WorkspaceId = item.WorkspaceId,
                Vector = vector,
                ContentHash = contentHash
            });

            // Invalidate stale existing matches if content changed
            if (existingEmbedding != null)
            {
                await matchingService.InvalidateMatchesAsync(item.Id!.Value, item.WorkspaceId);
            }
        }
    }

    private static async Task MarkCompleted(IMatchRepository matchRepository, MatchQueueEntry entry)
    {
        entry.Status = MatchQueueStatus.Completed;
        entry.ProcessedAt = DateTime.UtcNow;
        await matchRepository.UpdateQueueEntryAsync(entry);
    }
}
