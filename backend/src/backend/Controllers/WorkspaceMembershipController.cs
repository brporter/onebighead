using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Extensions;
using OneBigHead.Server.Middleware;
using OneBigHead.Server.Services.Memberships;

namespace OneBigHead.Server.Controllers;

[Authorize]
[Route("api/workspaces")]
public sealed class WorkspaceMembershipController(
    IWorkspaceAdminTransfer transfer,
    IWorkspaceLeave leave,
    IWorkspaceSwitch switching,
    ITokenService tokens,
    IOptions<AuthenticationSettings> settings) : ApiControllerBase
{
    [HttpPost("{workspaceId}/transfer-admin")]
    public async Task<ActionResult<TransferAdminResponse>> TransferAdmin(int workspaceId, TransferAdminRequest request)
    {
        if (TryGetUserId() is not > 0) return Unauthorized();
        var result = await transfer.TransferAsync(GetUserId(), workspaceId, request.NewAdminUserId);
        var response = new TransferAdminResponse { Success = result.Status == WorkspaceAdminTransferStatus.Transferred, Error = result.Error };
        switch (result.Status)
        {
            case WorkspaceAdminTransferStatus.NotFound: return NotFound(response);
            case WorkspaceAdminTransferStatus.Forbidden: return Forbid();
            case WorkspaceAdminTransferStatus.Invalid: return BadRequest(response);
            case WorkspaceAdminTransferStatus.Conflict: return Conflict(response);
        }

        SetSessionCookie(result.Session!);
        return Ok(response);
    }

    [AllowInactiveWorkspace]
    [HttpDelete("{workspaceId}/membership")]
    public async Task<IActionResult> LeaveWorkspace(int workspaceId)
    {
        if (TryGetUserId() is not > 0) return Unauthorized();
        var result = await leave.LeaveAsync(GetUserId(), workspaceId);
        switch (result.Status)
        {
            case WorkspaceLeaveStatus.NotFound: return NotFound(new { error = result.Error });
            case WorkspaceLeaveStatus.Invalid: return BadRequest(new { error = result.Error });
            case WorkspaceLeaveStatus.Conflict: return Conflict(new { error = result.Error });
        }

        SetSessionCookie(result.Session!);
        return Ok(new LeaveWorkspaceResponse { Success = true });
    }

    private void SetSessionCookie(CurrentUserSession session) =>
        Response.SetAuthCookie(tokens.GenerateAppToken(session.User, session.Response.WorkspaceRole), settings.Value);

    [AllowInactiveWorkspace]
    [HttpPost("{workspaceId}/switch")]
    public async Task<IActionResult> SwitchWorkspace(int workspaceId)
    {
        if (TryGetUserId() is not > 0) return Unauthorized();
        var result = await switching.SwitchAsync(GetUserId(), workspaceId);
        if (result.Status == WorkspaceSwitchStatus.Forbidden) return Forbid();
        if (result.Status == WorkspaceSwitchStatus.Conflict) return Conflict(new { error = result.Error });
        var session = result.Session!;
        SetSessionCookie(session);
        return Ok(new SwitchWorkspaceResponse
        {
            Success = true, WorkspaceId = workspaceId, WorkspaceName = session.Response.ActiveWorkspace!.WorkspaceName
        });
    }
}
