using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services.Matching;

[GenerateTracingProxy]
public interface IEmbeddingService
{
    Task<float[]> GenerateEmbeddingAsync(Item item, CancellationToken ct = default);
    string ComputeContentHash(Item item);
    double CosineSimilarity(float[] a, float[] b);
}
