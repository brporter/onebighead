using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services;

public record StoredImageInfo(Guid Key, string Url);

public record RetrievedImage(byte[] Data, string ContentType, string FileName);

[GenerateTracingProxy]
public interface IImageProvider
{
    Task<StoredImageInfo> StoreAsync(int workspaceId, string fileName, string contentType, Stream data);
    Task<RetrievedImage?> RetrieveAsync(Guid key, int workspaceId);
    Task<RetrievedImage?> RetrieveByKeyAsync(Guid key);
    Task DeleteAsync(Guid key, int workspaceId);
}
