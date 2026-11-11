using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Extensions;
using OneBigHead.Server.Middleware;
using OneBigHead.Server.Services.Invitations;

namespace OneBigHead.Server.Controllers;

[ApiController, Authorize, Route("api/invitations")]
public sealed class InvitationAccessController(IInvitationPreview preview, IInvitationAcceptance acceptance,
    ITokenService tokens, IOptions<AuthenticationSettings> settings) : ControllerBase
{
    [AllowAnonymous, AllowInactiveWorkspace, HttpPost("preview")]
    public async Task<IActionResult> Preview(InvitationAccessRequest request)
    {
        Response.Headers.CacheControl = "no-store";
        var invitation = await preview.ReadAsync(request, HttpContext.RequestAborted);
        return invitation is null ? NotFound(new { error = "This invitation is unavailable. Ask an administrator for a new link." }) : Ok(invitation);
    }

    [AllowInactiveWorkspace, HttpPost("accept")]
    public async Task<IActionResult> Accept(InvitationAccessRequest request)
    {
        if (!int.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var userId) || userId <= 0) return Unauthorized();
        var result = await acceptance.AcceptAsync(userId, request, HttpContext.RequestAborted);
        Response.Headers.CacheControl = "no-store";
        if (result.Status == InvitationAcceptanceStatus.Unauthenticated) return Unauthorized();
        if (result.Status == InvitationAcceptanceStatus.Invalid) return NotFound(new { error = "This invitation is unavailable. Ask an administrator for a new link." });
        if (result.Status == InvitationAcceptanceStatus.Conflict) return Conflict(new { error = "Invitation changed. Try joining again." });
        var session = result.Session!;
        Response.SetAuthCookie(tokens.GenerateAppToken(session.User, session.Response.WorkspaceRole), settings.Value);
        return Ok(session.Response);
    }
}
