using OneBigHead.Server.Services.Support;
using OneBigHead.Server.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
public class SupportController(ISupportRequestCreator creator, ISupportRequests requests, ISupportReplies replies) : ControllerBase
{
    [HttpPost]
    public async Task<ActionResult<SupportRequestDto>> CreateRequest([FromBody] CreateSupportRequestDto dto)
    {
        var result = await creator.CreateAsync(GetUserId(), dto);
        return result.Status switch
        {
            SupportCreationStatus.UnknownUser => Unauthorized(),
            SupportCreationStatus.MissingEmail => BadRequest(new { error = "Email is required for anonymous support requests." }),
            _ => CreatedAtAction(nameof(GetRequest), new { id = result.Request!.Id }, SupportRequestDto.FromEntity(result.Request))
        };
    }

    [Authorize]
    [HttpGet]
    public async Task<ActionResult<IEnumerable<SupportRequestDto>>> GetMyRequests()
    {
        var userId = GetUserId();
        if (!userId.HasValue) return Unauthorized();
        var result = await requests.GetForUserAsync(userId.Value);
        return Ok(result.Select(request => SupportRequestDto.FromEntity(request)));
    }

    [Authorize]
    [HttpGet("{id:int}")]
    public async Task<ActionResult<SupportRequestDto>> GetRequest(int id)
    {
        var userId = GetUserId();
        if (!userId.HasValue) return Unauthorized();
        var request = await requests.GetAsync(id, userId.Value);
        return request is null ? NotFound() : Ok(SupportRequestDto.FromEntity(request, includeReplies: true));
    }

    [Authorize]
    [HttpPost("{id:int}/reply")]
    public async Task<ActionResult<SupportReplyDto>> AddReply(int id, [FromBody] CreateSupportReplyDto dto)
    {
        var userId = GetUserId();
        if (!userId.HasValue) return Unauthorized();
        var result = await replies.AddUserReplyAsync(id, userId.Value, dto.Message);
        return result.Status switch
        {
            SupportReplyStatus.NotFound => NotFound(),
            SupportReplyStatus.Forbidden => Forbid(),
            SupportReplyStatus.Invalid => BadRequest(new { error = result.Error }),
            SupportReplyStatus.Conflict => Conflict(new { error = result.Error }),
            _ => Ok(result.Reply)
        };
    }

    [Authorize]
    [HttpDelete("{id:int}")]
    public async Task<IActionResult> DeleteRequest(int id)
    {
        var userId = GetUserId();
        if (!userId.HasValue) return Unauthorized();
        return await requests.DeleteAsync(id, userId.Value) ? NoContent() : NotFound();
    }

    [Authorize]
    [HttpGet("unread-count")]
    public async Task<ActionResult<SupportUnreadCountDto>> GetUnreadCount()
    {
        var userId = GetUserId();
        if (!userId.HasValue) return Unauthorized();
        var count = await requests.GetUnreadCountAsync(userId.Value);
        return Ok(new SupportUnreadCountDto { UnreadCount = count });
    }

    [Authorize]
    [HttpPost("{id:int}/mark-read")]
    public async Task<IActionResult> MarkAsRead(int id)
    {
        var userId = GetUserId();
        if (!userId.HasValue) return Unauthorized();
        return await requests.MarkReadAsync(id, userId.Value) ? NoContent() : NotFound();
    }

    private int? GetUserId()
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (int.TryParse(userIdClaim, out var userId) && userId > 0)
        {
            return userId;
        }
        return null;
    }
}
