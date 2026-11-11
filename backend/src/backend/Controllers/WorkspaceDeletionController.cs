using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Extensions;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Controllers;

[Authorize]
[Route("api/workspaces")]
public sealed class WorkspaceDeletionController(IWorkspaceDeletionService deletion, ITokenService tokens,
    IOptions<AuthenticationSettings> settings) : ApiControllerBase
{
    [HttpDelete("{workspaceId}")]
    public async Task<IActionResult> DeleteWorkspace(int workspaceId)
    {
        if (TryGetUserId() is not > 0) return Unauthorized();
        var result = await deletion.SoftDeleteWorkspaceAsync(workspaceId, GetUserId());
        switch (result.Status)
        {
            case WorkspaceDeletionStatus.NotFound: return NotFound(new { error = result.Error });
            case WorkspaceDeletionStatus.Forbidden: return Forbid();
            case WorkspaceDeletionStatus.Conflict: return Conflict(new { error = result.Error });
        }
        if (result.Response!.UserSoftDeleted) Response.ClearAuthCookie(settings.Value);
        else Response.SetAuthCookie(tokens.GenerateAppToken(result.Session!.User, result.Session.Response.WorkspaceRole), settings.Value);
        return Ok(result.Response);
    }
}
