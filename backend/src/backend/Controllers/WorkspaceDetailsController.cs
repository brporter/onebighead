using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Controllers;

[Authorize]
[Route("api/workspaces")]
public sealed class WorkspaceDetailsController(IWorkspaceDetails details) : ApiControllerBase
{
    [HttpPut("{workspaceId}")]
    public async Task<IActionResult> UpdateWorkspace(int workspaceId, UpdateWorkspaceRequest request)
    {
        if (TryGetUserId() is not > 0) return Unauthorized();
        var result = await details.UpdateAsync(GetUserId(), workspaceId, request);
        return result.Status switch
        {
            WorkspaceDetailsStatus.NotFound => NotFound(new { error = result.Error }),
            WorkspaceDetailsStatus.Forbidden => Forbid(),
            WorkspaceDetailsStatus.Invalid => BadRequest(new { error = result.Error }),
            WorkspaceDetailsStatus.Conflict => Conflict(new { error = result.Error }),
            _ => Ok(result.Workspace)
        };
    }
}
