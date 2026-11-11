using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OneBigHead.Server.Services.Invitations;

namespace OneBigHead.Server.Controllers;

[Authorize, Route("api/invitations")]
public sealed class WorkspaceInvitationsController(IInvitationDirectory directory, IInvitationCancellation cancellation) : ApiControllerBase
{
    [HttpGet]
    public async Task<IActionResult> List()
    {
        if (TryGetUserId() is not > 0 || TryGetWorkspaceId() is not > 0) return Unauthorized();
        var invitations = await directory.ReadAsync(GetUserId(), GetWorkspaceId());
        Response.Headers.CacheControl = "no-store";
        return invitations is null ? Forbid() : Ok(invitations);
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Cancel(Guid id)
    {
        if (TryGetUserId() is not > 0 || TryGetWorkspaceId() is not > 0) return Unauthorized();
        return await cancellation.CancelAsync(GetUserId(), GetWorkspaceId(), id) switch
        {
            InvitationCancellationStatus.Forbidden => Forbid(),
            InvitationCancellationStatus.NotFound => NotFound(),
            InvitationCancellationStatus.Conflict => Conflict(new { error = "Invitation changed. Refresh the invitation list." }),
            _ => NoContent()
        };
    }

}
