using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services;

[GenerateTracingProxy]
public interface IImageProvider
{
    Task<StoredImageInfo> StoreAsync(int workspaceId, string fileName, string contentType, Stream data);
    Task DeleteAsync(Guid key, int workspaceId);
}
