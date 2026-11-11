using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Controllers;

[Authorize]
[Route("api/auth/complete-welcome")]
public sealed class WorkspaceWelcomeController(IWorkspaceWelcome welcome) : ApiControllerBase
{
    [HttpPost]
    public async Task<IActionResult> CompleteWelcome(CompleteWelcomeRequest request)
    {
        if (TryGetUserId() is not > 0 || TryGetWorkspaceId() is not > 0) return Unauthorized();
        var result = await welcome.CompleteAsync(GetUserId(), GetWorkspaceId(), request);
        return result.Status switch
        {
            WorkspaceWelcomeStatus.NotFound => NotFound(new { error = result.Error }),
            WorkspaceWelcomeStatus.Forbidden => Forbid(),
            WorkspaceWelcomeStatus.Invalid => BadRequest(new { error = result.Error }),
            WorkspaceWelcomeStatus.Conflict => Conflict(new { error = result.Error }),
            _ => Ok(result.Workspace)
        };
    }
}
