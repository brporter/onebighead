using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services.Matching;

[GenerateTracingProxy]
public interface ILlmService
{
    Task<List<LlmMatchResult>> EvaluateMatchesAsync(
        Item wantItem, List<Item> candidates, CancellationToken ct = default);
}
