using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

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