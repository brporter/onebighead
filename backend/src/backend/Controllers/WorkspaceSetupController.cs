using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Extensions;
using OneBigHead.Server.Middleware;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Controllers;

[Authorize]
[Route("api/workspaces/setup")]
public sealed class WorkspaceSetupController(IWorkspaceSetup setup, ITokenService tokens,
    IOptions<AuthenticationSettings> settings) : ApiControllerBase
{
    [AllowInactiveWorkspace]
    [HttpPost]
    public async Task<IActionResult> SetupWorkspace(SetupWorkspaceRequest request)
    {
        if (TryGetUserId() is not > 0) return Unauthorized();
        var result = await setup.CreateAsync(GetUserId(), request);
        if (result.Status == WorkspaceSetupStatus.Forbidden) return Forbid();
        if (result.Status == WorkspaceSetupStatus.Invalid) return BadRequest(new { error = result.Error });
        if (result.Status == WorkspaceSetupStatus.Conflict) return Conflict(new { error = result.Error });
        if (result.Status == WorkspaceSetupStatus.Unavailable) return StatusCode(StatusCodes.Status410Gone, new { error = result.Error });
        var session = result.Session!;
        Response.SetAuthCookie(tokens.GenerateAppToken(session.User, session.Response.WorkspaceRole), settings.Value);
        return Ok(result.Workspace);
    }
}
