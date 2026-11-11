using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services.Images;

[GenerateTracingProxy]
public interface IImageReader
{
    Task<RetrievedImage?> ReadAsync(Guid key, int? userId, int? workspaceId, CancellationToken cancellationToken);
}
