using backend.Data;
using backend.DTOs;
using backend.Models;
using backend.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace backend.Controllers;

[ApiController]
[Route("api/admin/support")]
[Authorize(Roles = "SystemAdministrator")]
public class AdminSupportController : ControllerBase
{
    private readonly ISupportRepository _supportRepository;
    private readonly IEmailService _emailService;

    public AdminSupportController(
        ISupportRepository supportRepository,
        IEmailService emailService)
    {
        _supportRepository = supportRepository;
        _emailService = emailService;
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
        var request = await _supportRepository.GetRequestByIdAsync(id);
        if (request == null)
        {
            return NotFound();
        }

        if (request.IsDeleted)
        {
            return BadRequest(new { error = "Cannot reply to a deleted request." });
        }

        var adminUserId = GetUserId();

        var reply = new SupportReply
        {
            SupportRequestId = id,
            UserId = adminUserId,
            IsFromAdmin = true,
            Message = dto.Message,
            IsRead = false // Needs to be read by the user
        };

        var created = await _supportRepository.AddReplyAsync(reply);

        // Update status to InProgress if it was Open
        if (request.Status == SupportRequestStatus.Open)
        {
            await _supportRepository.UpdateStatusAsync(id, SupportRequestStatus.InProgress);
        }

        // Send email notification to the user
        var isLoggedInUser = request.UserId.HasValue;
        await _emailService.SendSupportReplyNotificationAsync(
            request.Email,
            request.Subject,
            dto.Message,
            request.Id,
            isLoggedInUser);

        return Ok(SupportReplyDto.FromEntity(created));
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
        if (int.TryParse(userIdClaim, out var userId))
        {
            return userId;
        }
        return null;
    }
}
