using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services.Memberships;

namespace OneBigHead.Server.Controllers;

[Authorize]
[Route("api/users")]
public sealed class TeamDirectoryController(ITeamDirectory directory, ITeamInvitations invitations) : ApiControllerBase
{
    [HttpGet]
    public async Task<IActionResult> GetUsers()
    {
        if (TryGetUserId() is not > 0 || TryGetWorkspaceId() is not > 0) return Unauthorized();
        var members = await directory.ReadAsync(GetUserId(), GetWorkspaceId());
        return members is null ? Forbid() : Ok(members);
    }

    [HttpPost]
    public async Task<IActionResult> InviteUser(InviteUserRequest request)
    {
        if (TryGetUserId() is not > 0 || TryGetWorkspaceId() is not > 0) return Unauthorized();
        var result = await invitations.InviteAsync(GetUserId(), GetWorkspaceId(), request);
        Response.Headers.CacheControl = "no-store";
        return result.Status switch
        {
            TeamInvitationStatus.Forbidden => Forbid(),
            TeamInvitationStatus.Invalid => BadRequest(new { error = result.Error }),
            TeamInvitationStatus.Conflict => Conflict(new { error = result.Error }),
            _ => CreatedAtAction(nameof(GetUsers), result.Invitation)
        };
    }
}
