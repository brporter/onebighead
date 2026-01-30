using backend.DTOs;
using backend.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace backend.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ImagesController : ApiControllerBase
{
    private readonly IImageProvider _imageProvider;
    
    private static readonly Dictionary<string, byte[][]> FileSignatures = new()
    {
        { "image/jpeg", new[] { new byte[] { 0xFF, 0xD8, 0xFF } } },
        { "image/jpg", new[] { new byte[] { 0xFF, 0xD8, 0xFF } } },
        { "image/png", new[] { new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A } } },
        { "image/gif", new[] { new byte[] { 0x47, 0x49, 0x46, 0x38, 0x37, 0x61 }, new byte[] { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 } } },
        { "image/webp", new[] { new byte[] { 0x52, 0x49, 0x46, 0x46 } } } // RIFF header, WebP also has WEBP at offset 8
    };

    private const long MaxFileSize = 10 * 1024 * 1024; // 10 MB

    public ImagesController(IImageProvider imageProvider)
    {
        _imageProvider = imageProvider;
    }

    private static bool VerifyFileSignature(byte[] fileData, string contentType)
    {
        if (!FileSignatures.TryGetValue(contentType.ToLowerInvariant(), out var signatures))
            return false;

        foreach (var signature in signatures)
        {
            if (fileData.Length >= signature.Length)
            {
                var headerMatches = true;
                for (int i = 0; i < signature.Length; i++)
                {
                    if (fileData[i] != signature[i])
                    {
                        headerMatches = false;
                        break;
                    }
                }
                
                if (headerMatches)
                {
                    // Additional check for WebP: verify WEBP marker at offset 8
                    if (contentType.Equals("image/webp", StringComparison.OrdinalIgnoreCase))
                    {
                        if (fileData.Length >= 12)
                        {
                            var webpMarker = new byte[] { 0x57, 0x45, 0x42, 0x50 }; // "WEBP"
                            var markerMatches = true;
                            for (int i = 0; i < 4; i++)
                            {
                                if (fileData[8 + i] != webpMarker[i])
                                {
                                    markerMatches = false;
                                    break;
                                }
                            }
                            return markerMatches;
                        }
                        return false;
                    }
                    return true;
                }
            }
        }
        
        return false;
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
    [RequestSizeLimit(MaxFileSize)]
    public async Task<ActionResult<ImageUploadResponse>> Upload(IFormFile file)
    {
        var tenantId = TryGetTenantId();
        if (tenantId == null)
        {
            return Unauthorized(new { error = "Invalid or missing tenant information" });
        }

        if (file == null || file.Length == 0)
        {
            return BadRequest(new { error = "No file provided" });
        }

        if (!FileSignatures.ContainsKey(file.ContentType.ToLowerInvariant()))
        {
            return BadRequest(new { error = $"Content type '{file.ContentType}' is not allowed. Allowed types: JPEG, PNG, GIF, WebP" });
        }

        // Read file into memory to verify signature
        using var memoryStream = new MemoryStream();
        await file.CopyToAsync(memoryStream);
        var fileData = memoryStream.ToArray();

        if (!VerifyFileSignature(fileData, file.ContentType))
        {
            return BadRequest(new { error = "File content does not match the declared file type. Please upload a valid image file." });
        }

        var sanitizedFileName = SanitizeFileName(file.FileName);

        using var dataStream = new MemoryStream(fileData);
        var result = await _imageProvider.StoreAsync(tenantId.Value, sanitizedFileName, file.ContentType, dataStream);

        return Ok(new ImageUploadResponse(result.Key, result.Url));
    }

    [HttpGet("{key:guid}")]
    [ResponseCache(Duration = 86400, Location = ResponseCacheLocation.Any, VaryByHeader = "Authorization")]
    public async Task<IActionResult> Get(Guid key)
    {
        var tenantId = TryGetTenantId();
        if (tenantId == null)
        {
            return Unauthorized(new { error = "Invalid or missing tenant information" });
        }

        var image = await _imageProvider.RetrieveAsync(key, tenantId.Value);
        if (image == null)
        {
            return NotFound();
        }

        return File(image.Data, image.ContentType, image.FileName);
    }

    [HttpDelete("{key:guid}")]
    public async Task<IActionResult> Delete(Guid key)
    {
        var tenantId = TryGetTenantId();
        if (tenantId == null)
        {
            return Unauthorized(new { error = "Invalid or missing tenant information" });
        }

        await _imageProvider.DeleteAsync(key, tenantId.Value);
        return NoContent();
    }
}
