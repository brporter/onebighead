using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
public class SupportController : ControllerBase
{
    private readonly ISupportRepository _supportRepository;
    private readonly IUserRepository _userRepository;
    private readonly IEmailService _emailService;

    public SupportController(
        ISupportRepository supportRepository,
        IUserRepository userRepository,
        IEmailService emailService)
    {
        _supportRepository = supportRepository;
        _userRepository = userRepository;
        _emailService = emailService;
    }

    /// <summary>
    /// Create a new support request. Works for both logged-in and anonymous users.
    /// </summary>
    [HttpPost]
    public async Task<ActionResult<SupportRequestDto>> CreateRequest([FromBody] CreateSupportRequestDto dto)
    {
        var userId = GetUserId();
        string email;
        bool isLoggedIn = false;

        if (userId.HasValue)
        {
            // Logged-in user - get email from their account
            var user = await _userRepository.GetByIdAsync(userId.Value);
            if (user == null)
            {
                return Unauthorized();
            }
            email = user.Email;
            isLoggedIn = true;
        }
        else
        {
            // Anonymous user - email is required
            if (string.IsNullOrWhiteSpace(dto.Email))
            {
                return BadRequest(new { error = "Email is required for anonymous support requests." });
            }
            email = dto.Email;
        }

        var request = new SupportRequest
        {
            UserId = userId,
            Email = email,
            Subject = dto.Subject,
            Description = dto.Description,
            Status = SupportRequestStatus.Open
        };

        var created = await _supportRepository.CreateRequestAsync(request);

        // Send confirmation email
        await _emailService.SendSupportRequestConfirmationAsync(
            email, 
            dto.Subject, 
            created.Id, 
            isLoggedIn);

        return CreatedAtAction(
            nameof(GetRequest), 
            new { id = created.Id }, 
            SupportRequestDto.FromEntity(created));
    }

    /// <summary>
    /// Get the current user's support requests.
    /// </summary>
    [Authorize]
    [HttpGet]
    public async Task<ActionResult<IEnumerable<SupportRequestDto>>> GetMyRequests()
    {
        var userId = GetUserId();
        if (!userId.HasValue)
        {
            return Unauthorized();
        }

        var requests = await _supportRepository.GetRequestsForUserAsync(userId.Value);
        return Ok(requests.Select(r => SupportRequestDto.FromEntity(r)));
    }

    /// <summary>
    /// Get a specific support request with replies.
    /// </summary>
    [Authorize]
    [HttpGet("{id:int}")]
    public async Task<ActionResult<SupportRequestDto>> GetRequest(int id)
    {
        var userId = GetUserId();
        if (!userId.HasValue)
        {
            return Unauthorized();
        }

        var request = await _supportRepository.GetRequestByIdAsync(id, includeReplies: true);
        if (request == null)
        {
            return NotFound();
        }

        // Users can only view their own requests
        if (request.UserId != userId.Value)
        {
            return Forbid();
        }

        // Note: Replies are NOT marked as read here. Use POST /mark-read endpoint explicitly.
        return Ok(SupportRequestDto.FromEntity(request, includeReplies: true));
    }

    /// <summary>
    /// Add a reply to a support request.
    /// </summary>
    [Authorize]
    [HttpPost("{id:int}/reply")]
    public async Task<ActionResult<SupportReplyDto>> AddReply(int id, [FromBody] CreateSupportReplyDto dto)
    {
        var userId = GetUserId();
        if (!userId.HasValue)
        {
            return Unauthorized();
        }

        var request = await _supportRepository.GetRequestByIdAsync(id);
        if (request == null)
        {
            return NotFound();
        }

        // Users can only reply to their own requests
        if (request.UserId != userId.Value)
        {
            return Forbid();
        }

        if (request.IsDeleted)
        {
            return BadRequest(new { error = "Cannot reply to a deleted request." });
        }

        var reply = new SupportReply
        {
            SupportRequestId = id,
            UserId = userId.Value,
            IsFromAdmin = false,
            Message = dto.Message,
            IsRead = true // User's own replies are considered read
        };

        var created = await _supportRepository.AddReplyAsync(reply);

        // Reopen the request if it was closed/resolved
        if (request.Status == SupportRequestStatus.Resolved || request.Status == SupportRequestStatus.Closed)
        {
            await _supportRepository.UpdateStatusAsync(id, SupportRequestStatus.Open);
        }

        return Ok(SupportReplyDto.FromEntity(created));
    }

    /// <summary>
    /// Soft delete a support request.
    /// </summary>
    [Authorize]
    [HttpDelete("{id:int}")]
    public async Task<IActionResult> DeleteRequest(int id)
    {
        var userId = GetUserId();
        if (!userId.HasValue)
        {
            return Unauthorized();
        }

        var request = await _supportRepository.GetRequestByIdAsync(id);
        if (request == null)
        {
            return NotFound();
        }

        // Users can only delete their own requests
        if (request.UserId != userId.Value)
        {
            return Forbid();
        }

        await _supportRepository.SoftDeleteAsync(id);
        return NoContent();
    }

    /// <summary>
    /// Get the count of unread admin replies for the current user.
    /// </summary>
    [Authorize]
    [HttpGet("unread-count")]
    public async Task<ActionResult<SupportUnreadCountDto>> GetUnreadCount()
    {
        var userId = GetUserId();
        if (!userId.HasValue)
        {
            return Unauthorized();
        }

        var count = await _supportRepository.GetUnreadCountForUserAsync(userId.Value);
        return Ok(new SupportUnreadCountDto { UnreadCount = count });
    }

    /// <summary>
    /// Mark all replies as read for a specific request.
    /// </summary>
    [Authorize]
    [HttpPost("{id:int}/mark-read")]
    public async Task<IActionResult> MarkAsRead(int id)
    {
        var userId = GetUserId();
        if (!userId.HasValue)
        {
            return Unauthorized();
        }

        var request = await _supportRepository.GetRequestByIdAsync(id);
        if (request == null)
        {
            return NotFound();
        }

        if (request.UserId != userId.Value)
        {
            return Forbid();
        }

        await _supportRepository.MarkRepliesAsReadAsync(id, userId.Value);
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
