using OneBigHead.Server.Services.Support;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Middleware;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/admin/support")]
[Authorize(Policy = SystemAdministratorRequirement.PolicyName)]
[AllowInactiveWorkspace]
public class AdminSupportController : ControllerBase
{
    private readonly ISupportRepository _supportRepository;
    private readonly ISupportReplies _replies;

    public AdminSupportController(
        ISupportRepository supportRepository,
        ISupportReplies replies)
    {
        _supportRepository = supportRepository;
        _replies = replies;
    }

    /// <summary>
    /// Get all support requests with optional filtering.
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<object>> GetAllRequests(
        [FromQuery] string? status = null,
        [FromQuery] bool includeDeleted = false,
        [FromQuery] int limit = 50,
        [FromQuery] int offset = 0)
    {
        SupportRequestStatus? statusFilter = null;
        if (!string.IsNullOrEmpty(status) && Enum.TryParse<SupportRequestStatus>(status, true, out var parsed))
        {
            statusFilter = parsed;
        }

        var requests = await _supportRepository.GetAllRequestsAsync(statusFilter, includeDeleted, limit, offset);
        var total = await _supportRepository.GetRequestCountAsync(statusFilter, includeDeleted);

        return Ok(new
        {
            items = requests.Select(r => SupportRequestDto.FromEntity(r)),
            total,
            limit,
            offset
        });
    }

    /// <summary>
    /// Get a specific support request with all replies.
    /// </summary>
    [HttpGet("{id:int}")]
    public async Task<ActionResult<SupportRequestDto>> GetRequest(int id)
    {
        var request = await _supportRepository.GetRequestByIdAsync(id, includeReplies: true);
        if (request == null)
        {
            return NotFound();
        }

        return Ok(SupportRequestDto.FromEntity(request, includeReplies: true));
    }

    /// <summary>
    /// Add an admin reply to a support request and notify the user.
    /// </summary>
    [HttpPost("{id:int}/reply")]
    public async Task<ActionResult<SupportReplyDto>> AddReply(int id, [FromBody] CreateSupportReplyDto dto)
    {
        var userId = GetUserId();
        if (!userId.HasValue) return Unauthorized();
        var result = await _replies.AddAdminReplyAsync(id, userId.Value, dto.Message);
        return result.Status switch
        {
            SupportReplyStatus.NotFound => NotFound(),
            SupportReplyStatus.Forbidden => Forbid(),
            SupportReplyStatus.Invalid => BadRequest(new { error = result.Error }),
            SupportReplyStatus.Conflict => Conflict(new { error = result.Error }),
            _ => Ok(result.Reply)
        };
    }

    /// <summary>
    /// Update the status of a support request.
    /// </summary>
    [HttpPut("{id:int}/status")]
    public async Task<ActionResult<SupportRequestDto>> UpdateStatus(int id, [FromBody] UpdateSupportStatusDto dto)
    {
        var request = await _supportRepository.UpdateStatusAsync(id, dto.Status);
        if (request == null)
        {
            return NotFound();
        }

        return Ok(SupportRequestDto.FromEntity(request));
    }

    /// <summary>
    /// Soft delete a support request.
    /// </summary>
    [HttpDelete("{id:int}")]
    public async Task<IActionResult> DeleteRequest(int id)
    {
        var success = await _supportRepository.SoftDeleteAsync(id);
        if (!success)
        {
            return NotFound();
        }

        return NoContent();
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
