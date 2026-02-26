using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Matching;

public class MatchingService : IMatchingService
{
    private readonly IMatchRepository _matchRepository;
    private readonly IItemEmbeddingRepository _embeddingRepository;
    private readonly IItemRepository _itemRepository;
    private readonly IEmbeddingService _embeddingService;
    private readonly ILogger<MatchingService> _logger;

    public MatchingService(
        IMatchRepository matchRepository,
        IItemEmbeddingRepository embeddingRepository,
        IItemRepository itemRepository,
        IEmbeddingService embeddingService,
        ILogger<MatchingService> logger)
    {
        _matchRepository = matchRepository;
        _embeddingRepository = embeddingRepository;
        _itemRepository = itemRepository;
        _embeddingService = embeddingService;
        _logger = logger;
    }

    public async Task EnqueueForMatchingAsync(int itemId, int workspaceId, MatchQueueReason reason)
    {
        var entry = new MatchQueueEntry
        {
            ItemId = itemId,
            WorkspaceId = workspaceId,
            Reason = reason,
            Status = MatchQueueStatus.Pending
        };

        await _matchRepository.EnqueueAsync(entry);
        await _matchRepository.DeduplicateQueueAsync(itemId);
    }

    public async Task<List<(Item Item, double Similarity)>> FindCandidatesAsync(Item wantItem)
    {
        var wantEmbedding = await _embeddingRepository.GetByItemIdAsync(wantItem.Id!.Value);
        if (wantEmbedding == null)
        {
            _logger.LogWarning("No embedding found for want item {ItemId}", wantItem.Id);
            return [];
        }

        var tradeEmbeddings = await _embeddingRepository.GetAllForTradeOrSellAsync(wantItem.WorkspaceId);
        if (tradeEmbeddings.Count == 0)
            return [];

        var candidates = new List<(int ItemId, double Similarity)>();

        foreach (var tradeEmbedding in tradeEmbeddings)
        {
            var similarity = _embeddingService.CosineSimilarity(wantEmbedding.Vector, tradeEmbedding.Vector);
            if (similarity >= 0.5) // SimilarityThreshold applied at worker level with settings
            {
                candidates.Add((tradeEmbedding.ItemId, similarity));
            }
        }

        // Sort by similarity descending and take top candidates
        candidates.Sort((a, b) => b.Similarity.CompareTo(a.Similarity));
        if (candidates.Count > 10)
            candidates = candidates.Take(10).ToList();

        // Load full item data for candidates
        var result = new List<(Item Item, double Similarity)>();
        foreach (var (itemId, similarity) in candidates)
        {
            var item = await _itemRepository.GetByIdCrossWorkspaceAsync(itemId);
            if (item != null)
            {
                result.Add((item, similarity));
            }
        }

        return result;
    }

    public async Task RemoveMatchesForItemAsync(int itemId)
    {
        await _matchRepository.DeleteByItemIdAsync(itemId);
        await _embeddingRepository.DeleteByItemIdAsync(itemId);
    }

    public async Task InvalidateMatchesAsync(int itemId, int workspaceId)
    {
        // When a TradeOrSell item's content changes, we need to re-evaluate
        // existing matches that reference this item
        var matches = await _matchRepository.GetMatchesForItemAsync(itemId);
        foreach (var match in matches)
        {
            // Reset to New so users re-evaluate
            if (match.TradeItemId == itemId)
            {
                match.WantUserStatus = MatchStatus.New;
                match.TradeUserStatus = MatchStatus.New;
                await _matchRepository.UpdateAsync(match);
            }
        }
    }
}
