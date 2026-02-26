using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Data;

[GenerateTracingProxy]
public interface IMatchRepository
{
    Task<ItemMatch?> GetByIdAsync(int matchId);
    Task<ItemMatch?> GetByItemPairAsync(int wantItemId, int tradeItemId);
    Task<ItemMatch> CreateAsync(ItemMatch match);
    Task UpdateAsync(ItemMatch match);
    Task DeleteByItemIdAsync(int itemId);
    Task<List<ItemMatch>> GetMatchesForWorkspaceAsync(int workspaceId, MatchStatus? status, int skip, int take);
    Task<int> GetNewMatchCountAsync(int workspaceId);
    Task<List<ItemMatch>> GetMatchesForItemAsync(int itemId);
    Task<MatchQueueEntry> EnqueueAsync(MatchQueueEntry entry);
    Task<List<MatchQueueEntry>> DequeueAsync(int batchSize);
    Task UpdateQueueEntryAsync(MatchQueueEntry entry);
    Task DeduplicateQueueAsync(int itemId);
}
