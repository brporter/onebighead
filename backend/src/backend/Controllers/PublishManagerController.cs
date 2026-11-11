using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services.Publishing;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/workspaces/{workspaceId}/publish")]
[Authorize]
public class PublishManagerController(IPublicationService service) : ApiControllerBase
{
    [HttpPost("preflight")]
    public async Task<IActionResult> Preflight(int workspaceId, [FromBody] PreflightRequest request, CancellationToken cancellationToken = default)
    {
        if (GetWorkspaceId() != workspaceId) return Forbid();
        return MapResult(await service.PreflightAsync(workspaceId, request, cancellationToken));
    }

    [HttpPost("execute")]
    public async Task<IActionResult> Execute(int workspaceId, [FromBody] ExecuteRequest request, CancellationToken cancellationToken = default)
    {
        if (GetWorkspaceId() != workspaceId) return Forbid();
        return MapResult(await service.ExecuteAsync(workspaceId, request, cancellationToken));
    }

    private IActionResult MapResult<T>(PublicationResult<T> result) => result.Error?.Kind switch
    {
        null => Ok(result.Value),
        PublicationFailure.Invalid => BadRequest(new { error = result.Error.Message }),
        PublicationFailure.NotFound => NotFound(new { error = result.Error.Message }),
        PublicationFailure.Conflict => Conflict(new { error = result.Error.Message }),
        _ => throw new ArgumentOutOfRangeException(nameof(result))
    };
}
