using backend.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace backend.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ImagesController : ControllerBase
{
    private readonly IImageProvider _imageProvider;
    private static readonly HashSet<string> AllowedContentTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "image/jpeg",
        "image/jpg",
        "image/png",
        "image/gif",
        "image/webp",
        "image/svg+xml"
    };

    private const long MaxFileSize = 10 * 1024 * 1024; // 10 MB

    public ImagesController(IImageProvider imageProvider)
    {
        _imageProvider = imageProvider;
    }

    private int GetTenantId()
    {
        var tenantIdClaim = User.FindFirst("tenant_id")?.Value;
        if (string.IsNullOrEmpty(tenantIdClaim) || !int.TryParse(tenantIdClaim, out var tenantId))
        {
            throw new UnauthorizedAccessException("Tenant ID not found in token");
        }
        return tenantId;
    }

    [HttpPost]
    [Authorize]
    [RequestSizeLimit(MaxFileSize)]
    public async Task<ActionResult<ImageUploadResponse>> Upload(IFormFile file)
    {
        if (file == null || file.Length == 0)
        {
            return BadRequest("No file provided");
        }

        if (file.Length > MaxFileSize)
        {
            return BadRequest($"File size exceeds the maximum allowed size of {MaxFileSize / 1024 / 1024} MB");
        }

        if (!AllowedContentTypes.Contains(file.ContentType))
        {
            return BadRequest($"Content type '{file.ContentType}' is not allowed. Allowed types: {string.Join(", ", AllowedContentTypes)}");
        }

        var tenantId = GetTenantId();

        await using var stream = file.OpenReadStream();
        var result = await _imageProvider.StoreAsync(tenantId, file.FileName, file.ContentType, stream);

        return Ok(new ImageUploadResponse(result.Key, result.Url));
    }

    [HttpGet("{key:guid}")]
    [AllowAnonymous]
    [ResponseCache(Duration = 86400, Location = ResponseCacheLocation.Any)]
    public async Task<IActionResult> Get(Guid key)
    {
        var image = await _imageProvider.RetrieveAsync(key);
        if (image == null)
        {
            return NotFound();
        }

        return File(image.Data, image.ContentType, image.FileName);
    }

    [HttpDelete("{key:guid}")]
    [Authorize]
    public async Task<IActionResult> Delete(Guid key)
    {
        await _imageProvider.DeleteAsync(key);
        return NoContent();
    }
}

public record ImageUploadResponse(Guid Key, string Url);
