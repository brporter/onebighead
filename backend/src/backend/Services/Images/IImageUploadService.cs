namespace OneBigHead.Server.Services.Images;

public sealed record ImageUploadResult(StoredImageInfo? Image = null, string? Error = null);

public interface IImageUploadService
{
    Task<ImageUploadResult> UploadAsync(int workspaceId, int? userId, string fileName, byte[] data);
}
