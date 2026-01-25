namespace backend.Services;

public record StoredImageInfo(Guid Key, string Url);

public record RetrievedImage(Stream Data, string ContentType, string FileName);

public interface IImageProvider
{
    Task<StoredImageInfo> StoreAsync(int tenantId, string fileName, string contentType, Stream data);
    Task<RetrievedImage?> RetrieveAsync(Guid key);
    Task DeleteAsync(Guid key);
}
