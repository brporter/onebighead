using backend.DTOs;
using OneBigHead.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/workspaces/{workspaceId}/publish")]
[Authorize]
public class PublishManagerController : ApiControllerBase
{
    private readonly IPublishManagerService _publishManagerService;

    public PublishManagerController(IPublishManagerService publishManagerService)
    {
        _publishManagerService = publishManagerService;
    }

    [HttpPost("preflight")]
    public async Task<IActionResult> Preflight(int workspaceId, [FromBody] PreflightRequest request)
    {
        var wsId = GetWorkspaceId();
        if (wsId != workspaceId) return Forbid();

        var result = await _publishManagerService.PreflightAsync(workspaceId, request);
        return Ok(result);
    }

    [HttpPost("execute")]
    public async Task<IActionResult> Execute(int workspaceId, [FromBody] ExecuteRequest request)
    {
        var wsId = GetWorkspaceId();
        if (wsId != workspaceId) return Forbid();

        var result = await _publishManagerService.ExecuteAsync(workspaceId, request);
        return Ok(result);
    }
}
