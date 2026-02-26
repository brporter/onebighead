using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services.Matching;

[GenerateTracingProxy]
public interface IMatchingService
{
    Task EnqueueForMatchingAsync(int itemId, int workspaceId, MatchQueueReason reason);
    Task<List<(Item Item, double Similarity)>> FindCandidatesAsync(Item wantItem);
    Task RemoveMatchesForItemAsync(int itemId);
    Task InvalidateMatchesAsync(int itemId, int workspaceId);
}
