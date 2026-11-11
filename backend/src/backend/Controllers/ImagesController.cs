using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services;
using OneBigHead.Server.Services.Images;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ImagesController(IImageProvider imageProvider, IImageReader imageReader, IImageUploadService uploads) : ApiControllerBase
{
    private const long MaxFileSize = 100 * 1024 * 1024;

    [HttpPost]
    [Authorize]
    [RequestSizeLimit(MaxFileSize)]
    public async Task<ActionResult<ImageUploadResponse>> Upload(IFormFile file)
    {
        var workspaceId = TryGetWorkspaceId();
        if (workspaceId is null) return Unauthorized(new { error = "Invalid or missing workspace information" });
        if (file is null || file.Length == 0) return BadRequest(new { error = "No file provided" });

        using var stream = new MemoryStream();
        await file.CopyToAsync(stream);
        var result = await uploads.UploadAsync(workspaceId.Value, TryGetUserId(), file.FileName, stream.ToArray());
        return result.Error is not null
            ? BadRequest(new { error = result.Error })
            : Ok(new ImageUploadResponse(result.Image!.Key, result.Image.Url));
    }

    [HttpGet("{key:guid}")]
    [AllowAnonymous]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> Get(Guid key)
    {
        var userId = User.Identity?.IsAuthenticated == true ? TryGetUserId() : null;
        var image = await imageReader.ReadAsync(key, userId, TryGetWorkspaceId(), HttpContext.RequestAborted);
        return image is null ? NotFound() : File(image.Data, image.ContentType, image.FileName);
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

        await imageProvider.DeleteAsync(key, workspaceId.Value);
        return NoContent();
    }
}
