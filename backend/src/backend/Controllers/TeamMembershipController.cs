using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services.Memberships;

namespace OneBigHead.Server.Controllers;

[Authorize]
[Route("api/users")]
public sealed class TeamMembershipController(ITeamRoleChanges roles, ITeamMemberRemoval removal) : ApiControllerBase
{
    [HttpPut("{id}/role")]
    public async Task<IActionResult> UpdateUserRole(int id, UpdateUserRoleRequest request)
    {
        if (TryGetUserId() is not > 0 || TryGetWorkspaceId() is not > 0) return Unauthorized();
        return Map(await roles.ChangeRoleAsync(GetUserId(), GetWorkspaceId(), id, request.Role));
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> RemoveUser(int id)
    {
        if (TryGetUserId() is not > 0 || TryGetWorkspaceId() is not > 0) return Unauthorized();
        return Map(await removal.RemoveAsync(GetUserId(), GetWorkspaceId(), id));
    }

    private IActionResult Map(TeamMembershipResult result) => result.Status switch
    {
        TeamMembershipStatus.Forbidden => Forbid(),
        TeamMembershipStatus.NotFound => NotFound(new { error = result.Error }),
        TeamMembershipStatus.Invalid => BadRequest(new { error = result.Error }),
        TeamMembershipStatus.Conflict => Conflict(new { error = result.Error }),
        _ => NoContent()
    };
}
