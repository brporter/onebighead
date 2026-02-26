using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Data;

[GenerateTracingProxy]
public interface IMatchMessageRepository
{
    Task<List<MatchMessage>> GetByMatchIdAsync(int matchId, int skip, int take);
    Task<MatchMessage> CreateAsync(MatchMessage message);
    Task MarkAsReadAsync(int matchId, int readerWorkspaceId);
    Task<int> GetUnreadCountAsync(int workspaceId);
}
