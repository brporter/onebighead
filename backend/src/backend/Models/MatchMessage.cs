using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.Models;

public class MatchMessage
{
    [Key]
    public int Id { get; set; }
    public int ItemMatchId { get; set; }
    public int SenderUserId { get; set; }
    public int SenderWorkspaceId { get; set; }
    [Required]
    [MaxLength(2000)]
    public string Message { get; set; } = string.Empty;
    public bool IsRead { get; set; } = false;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public ItemMatch? ItemMatch { get; set; }
}
