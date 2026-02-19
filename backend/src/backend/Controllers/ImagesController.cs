using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SkiaSharp;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ImagesController : ApiControllerBase
{
    private readonly IImageProvider _imageProvider;
    private readonly IImageProcessor _imageProcessor;

    private static readonly Dictionary<SKEncodedImageFormat, string> AllowedFormats = new()
    {
        { SKEncodedImageFormat.Jpeg, "image/jpeg" },
        { SKEncodedImageFormat.Png,  "image/png"  },
        { SKEncodedImageFormat.Gif,  "image/gif"  },
        { SKEncodedImageFormat.Webp, "image/webp" },
        { SKEncodedImageFormat.Avif, "image/avif" },
    };

    private const long MaxFileSize = 100 * 1024 * 1024; // 100 MB

    public ImagesController(IImageProvider imageProvider, IImageProcessor imageProcessor)
    {
        _imageProvider = imageProvider;
        _imageProcessor = imageProcessor;
    }

    private static string? DetectImageFormat(byte[] fileData)
    {
        using var data = SKData.CreateCopy(fileData);
        using var codec = SKCodec.Create(data);
        if (codec == null)
            return null;

        return AllowedFormats.GetValueOrDefault(codec.EncodedFormat);
    }

    private static string SanitizeFileName(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
            return "image";

        // Get just the filename without any path components
        fileName = Path.GetFileName(fileName);

        // Remove null bytes and control characters
        fileName = new string(fileName.Where(c => c >= 32 && c != 127).ToArray());

        // Replace unsafe characters with underscores
        var invalidChars = Path.GetInvalidFileNameChars()
            .Concat(new[] { '/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0' })
            .ToHashSet();

        var sanitized = new string(fileName.Select(c => invalidChars.Contains(c) ? '_' : c).ToArray());

        // Remove leading/trailing dots and spaces
        sanitized = sanitized.Trim('.', ' ');

        // Limit length
        if (sanitized.Length > 200)
        {
            var extension = Path.GetExtension(sanitized);
            var name = Path.GetFileNameWithoutExtension(sanitized);
            var maxNameLength = 200 - extension.Length;
            sanitized = name[..Math.Min(name.Length, maxNameLength)] + extension;
        }

        return string.IsNullOrWhiteSpace(sanitized) ? "image" : sanitized;
    }

    [HttpPost]
    [Authorize]
    [RequestSizeLimit(MaxFileSize)]
    public async Task<ActionResult<ImageUploadResponse>> Upload(IFormFile file)
    {
        var workspaceId = TryGetWorkspaceId();
        if (workspaceId == null)
        {
            return Unauthorized(new { error = "Invalid or missing workspace information" });
        }

        if (file == null || file.Length == 0)
        {
            return BadRequest(new { error = "No file provided" });
        }

        using var memoryStream = new MemoryStream();
        await file.CopyToAsync(memoryStream);
        var fileData = memoryStream.ToArray();

        var detectedContentType = DetectImageFormat(fileData);
        if (detectedContentType == null)
        {
            return BadRequest(new { error = "File is not a valid image or uses an unsupported format. Supported formats: JPEG, PNG, GIF, WebP, AVIF" });
        }

        var (processedData, processedContentType) = _imageProcessor.ResizeIfNeeded(fileData, detectedContentType);

        var sanitizedFileName = SanitizeFileName(file.FileName);

        using var dataStream = new MemoryStream(processedData);
        var result = await _imageProvider.StoreAsync(workspaceId.Value, sanitizedFileName, processedContentType, dataStream);

        return Ok(new ImageUploadResponse(result.Key, result.Url));
    }

    [HttpGet("{key:guid}")]
    [AllowAnonymous]
    [ResponseCache(Duration = 86400, Location = ResponseCacheLocation.Any)]
    public async Task<IActionResult> Get(Guid key)
    {
        // If user is authenticated with a workspace, try workspace-scoped retrieval first
        var workspaceId = TryGetWorkspaceId();
        if (workspaceId != null)
        {
            var image = await _imageProvider.RetrieveAsync(key, workspaceId.Value);
            if (image != null)
                return File(image.Data, image.ContentType, image.FileName);
        }

        // Fall back to public access: only serves images from public-enabled workspaces
        var publicImage = await _imageProvider.RetrievePublicAsync(key);
        if (publicImage != null)
            return File(publicImage.Data, publicImage.ContentType, publicImage.FileName);

        return NotFound();
    }

    [HttpDelete("{key:guid}")]
    [Authorize]
    public async Task<IActionResult> Delete(Guid key)
    {
        var workspaceId = TryGetWorkspaceId();
        if (workspaceId == null)
        {
            return Unauthorized(new { error = "Invalid or missing workspace information" });
        }

        await _imageProvider.DeleteAsync(key, workspaceId.Value);
        return NoContent();
    }
}
