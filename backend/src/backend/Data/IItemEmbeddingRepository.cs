using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Data;

[GenerateTracingProxy]
public interface IItemEmbeddingRepository
{
    Task<ItemEmbedding?> GetByItemIdAsync(int itemId);
    Task<List<ItemEmbedding>> GetAllForTradeOrSellAsync(int excludeWorkspaceId);
    Task<ItemEmbedding> UpsertAsync(ItemEmbedding embedding);
    Task DeleteByItemIdAsync(int itemId);
}
