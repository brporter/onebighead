using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Middleware;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Controllers;

[Authorize]
[Route("api/workspaces")]
public sealed class WorkspaceCreationController(IWorkspaceCreation creation) : ApiControllerBase
{
    [AllowInactiveWorkspace]
    [HttpPost]
    public async Task<IActionResult> CreateWorkspace(CreateWorkspaceRequest request)
    {
        if (TryGetUserId() is not > 0) return Unauthorized();
        var result = await creation.CreateAsync(GetUserId(), request);
        return result.Status switch
        {
            WorkspaceCreationStatus.Forbidden => Forbid(),
            WorkspaceCreationStatus.Invalid => BadRequest(new { error = result.Error }),
            WorkspaceCreationStatus.Conflict => Conflict(new { error = result.Error }),
            _ => Ok(result.Workspace)
        };
    }
}
