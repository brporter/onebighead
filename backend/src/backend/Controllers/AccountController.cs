using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Extensions;
using OneBigHead.Server.Middleware;
using OneBigHead.Server.Services.Accounts;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Authorize]
[AllowInactiveWorkspace]
[Route("api/users/me")]
public sealed class AccountController(
    IAccountDeletionReader reader,
    IAccountDeletion deletion,
    IOptions<AuthenticationSettings> settings) : ControllerBase
{
    [HttpGet("deletion-info")]
    public async Task<ActionResult<UserDeletionInfoResponse>> GetDeletionInfo()
    {
        if (GetUserId() is not int userId) return Unauthorized();
        var info = await reader.ReadAsync(userId);
        return info is null ? NotFound(new { error = "User not found" }) : Ok(info);
    }

    [HttpDelete]
    public async Task<ActionResult<DeleteUserResponse>> DeleteAccount(DeleteUserRequest request)
    {
        if (GetUserId() is not int userId) return Unauthorized();
        var result = await deletion.DeleteAsync(userId, request);
        var response = new DeleteUserResponse { Success = result.Status == AccountDeletionStatus.Deleted, Error = result.Error };
        if (result.Status == AccountDeletionStatus.Conflict) return Conflict(response);
        if (!response.Success) return BadRequest(response);
        Response.ClearAuthCookie(settings.Value);
        return Ok(response);
    }

    private int? GetUserId() => int.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var id) && id > 0 ? id : null;
}
