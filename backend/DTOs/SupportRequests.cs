using System.ComponentModel.DataAnnotations;
using backend.Models;

namespace backend.DTOs;

public class CreateSupportRequestDto
{
    [Required]
    [MaxLength(200)]
    public string Subject { get; set; } = string.Empty;

    [Required]
    [MaxLength(4000)]
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Required for anonymous users, optional for logged-in users.
    /// </summary>
    [MaxLength(320)]
    [EmailAddress]
    public string? Email { get; set; }
}

public class CreateSupportReplyDto
{
    [Required]
    [MaxLength(4000)]
    public string Message { get; set; } = string.Empty;
}

public class UpdateSupportStatusDto
{
    [Required]
    public SupportRequestStatus Status { get; set; }
}

public class SupportRequestDto
{
    public int SupportRequestId { get; set; }
    public int? UserId { get; set; }
    public string Email { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public bool IsDeleted { get; set; }
    public int ReplyCount { get; set; }
    public int UnreadCount { get; set; }
    public List<SupportReplyDto> Replies { get; set; } = new();

    public static SupportRequestDto FromEntity(SupportRequest request, bool includeReplies = false)
    {
        var dto = new SupportRequestDto
        {
            SupportRequestId = request.Id,
            UserId = request.UserId,
            Email = request.Email,
            Subject = request.Subject,
            Description = request.Description,
            Status = request.Status.ToString(),
            CreatedAt = request.CreatedAt,
            UpdatedAt = request.UpdatedAt,
            IsDeleted = request.IsDeleted,
            ReplyCount = request.Replies?.Count ?? 0,
            UnreadCount = request.Replies?.Count(r => r.IsFromAdmin && !r.IsRead) ?? 0
        };

        if (includeReplies && request.Replies != null)
        {
            dto.Replies = request.Replies
                .OrderBy(r => r.CreatedAt)
                .Select(SupportReplyDto.FromEntity)
                .ToList();
        }

        return dto;
    }
}

public class SupportReplyDto
{
    public int SupportReplyId { get; set; }
    public int SupportRequestId { get; set; }
    public int? UserId { get; set; }
    public bool IsFromAdmin { get; set; }
    public string Message { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public bool IsRead { get; set; }

    public static SupportReplyDto FromEntity(SupportReply reply)
    {
        return new SupportReplyDto
        {
            SupportReplyId = reply.Id,
            SupportRequestId = reply.SupportRequestId,
            UserId = reply.UserId,
            IsFromAdmin = reply.IsFromAdmin,
            Message = reply.Message,
            CreatedAt = reply.CreatedAt,
            IsRead = reply.IsRead
        };
    }
}

public class SupportUnreadCountDto
{
    public int UnreadCount { get; set; }
}
