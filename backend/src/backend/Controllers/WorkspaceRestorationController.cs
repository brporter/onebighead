using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Extensions;
using OneBigHead.Server.Middleware;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Controllers;

/// <summary>Cross-workspace recovery remains available without an active workspace.</summary>
[ApiController]
[Authorize]
[AllowInactiveWorkspace]
[Route("api/workspaces")]
public sealed class WorkspaceRestorationController(
    IWorkspaceRestorationService restoration,
    ITokenService tokens,
    IOptions<AuthenticationSettings> settings) : ControllerBase
{
    [HttpPost("restore")]
    public async Task<IActionResult> RestoreWorkspaces([FromBody] RestoreWorkspacesRequest request, CancellationToken cancellationToken)
    {
        if (!int.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
            return Unauthorized();
        if (request.WorkspaceIds is null || request.WorkspaceIds.Count == 0)
            return BadRequest(new { error = "At least one workspace ID is required" });

        var result = await restoration.RestoreAndActivateAsync(userId, request.WorkspaceIds, cancellationToken);
        if (!result.IsAuthorized) return Forbid();
        if (result.ActiveUser is not null)
            Response.SetAuthCookie(tokens.GenerateAppToken(result.ActiveUser, WorkspaceRole.WorkspaceAdmin), settings.Value);

        return Ok(new RestoreWorkspacesResponse
        {
            RestoredWorkspaceIds = result.RestoredWorkspaces.Select(w => w.Id).ToList(),
            ActiveWorkspaceId = result.ActiveUser?.ActiveWorkspaceId ?? 0
        });
    }

    [HttpPost("{workspaceId:int}/restore")]
    public async Task<IActionResult> RestoreWorkspace(int workspaceId, CancellationToken cancellationToken)
    {
        if (!int.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
            return Unauthorized();

        var result = await restoration.RestoreAsync(userId, workspaceId, cancellationToken);
        if (!result.IsAuthorized) return Forbid();
        if (result.RestoredWorkspaces.Count == 0)
            return BadRequest(new { error = "Workspace is not deleted" });

        var workspace = result.RestoredWorkspaces[0];
        return Ok(new RestoreWorkspaceResponse { WorkspaceId = workspace.Id, Name = workspace.Name });
    }
}
