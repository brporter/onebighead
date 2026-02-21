using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

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