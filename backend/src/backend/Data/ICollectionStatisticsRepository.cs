using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Data;

[GenerateTracingProxy]
public interface ICollectionStatisticsRepository
{
    Task IncrementAsync(int collectionId, CollectionStatisticType type, long amount = 1);
    Task DecrementAsync(int collectionId, CollectionStatisticType type, long amount = 1);
    Task<Dictionary<CollectionStatisticType, long>> GetAggregatesAsync(int collectionId);
    Task IncrementItemViewAsync(int collectionId, int itemId);
    Task<List<CollectionItemHighlight>> GetTopViewedItemsAsync(int collectionId, int count = 10);
    Task<List<Item>> GetRecentlyAddedItemsAsync(int collectionId, int workspaceId, int count = 10);
    Task RemoveItemHighlightAsync(int collectionId, int itemId);
    Task DeleteCollectionStatsAsync(int collectionId);
}
