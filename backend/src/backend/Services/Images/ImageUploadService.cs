using System.Security.Cryptography;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Images;

/// <summary>Validates and scans original bytes before processing or storing an upload.</summary>
public sealed class ImageUploadService(
    IImageFormatDetector formats,
    IContentScanner scanner,
    IContentScanLogRepository scanLogs,
    ICsamReportingService reporting,
    IImageProcessor processor,
    IImageProvider images,
    TimeProvider clock,
    ILogger<ImageUploadService> logger) : IImageUploadService
{
    public async Task<ImageUploadResult> UploadAsync(int workspaceId, int? userId, string fileName, byte[] data)
    {
        var contentType = formats.Detect(data);
        if (contentType is null)
            return new(Error: "File is not a valid image or uses an unsupported format. Supported formats: JPEG, PNG, GIF, WebP, AVIF");

        ContentScanResult result;
        try
        {
            result = await scanner.ScanAsync(data, contentType);
        }
        catch (Exception error)
        {
            logger.LogError(error, "Content scanner threw an exception. Rejecting upload (fail-closed).");
            return new(Error: "Unable to process this image. Please try again later.");
        }

        if (result.IsMatch)
        {
            var log = new ContentScanLog
            {
                Id = Guid.NewGuid(), WorkspaceId = workspaceId, UserId = userId,
                ScannerName = result.ScannerName, IsMatch = true, MatchScore = result.MatchScore,
                Details = result.Details, OriginalFileName = fileName, ContentType = contentType,
                FileSizeBytes = data.Length, ImageHash = Convert.ToHexString(SHA256.HashData(data)),
                ScannedAt = clock.GetUtcNow().UtcDateTime,
            };
            await scanLogs.CreateAsync(log);
            try
            {
                await reporting.ReportAsync(log);
            }
            catch (Exception error)
            {
                logger.LogError(error, "Failed to report CSAM scan log for image {ImageHash} (ScanLogId: {ScanLogId})", log.ImageHash, log.Id);
            }
            return new(Error: "Unable to process this image.");
        }

        var (processed, processedType) = processor.ResizeIfNeeded(data, contentType);
        using var stream = new MemoryStream(processed);
        var image = await images.StoreAsync(workspaceId, ImageFileName.Sanitize(fileName), processedType, stream);
        return new(Image: image);
    }
}
