using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace OneBigHead.Server.Models;

public class SupportReply
{
    [Key]
    [JsonPropertyName("supportReplyId")]
    public int Id { get; set; }

    public int SupportRequestId { get; set; }

    /// <summary>
    /// The user who posted this reply. For admin replies, this is the admin user.
    /// For user replies, this is the requesting user. Null only if user was deleted.
    /// </summary>
    public int? UserId { get; set; }

    /// <summary>
    /// True if this reply was posted by an admin, false if by the requesting user.
    /// </summary>
    public bool IsFromAdmin { get; set; }

    [Required]
    [MaxLength(4000)]
    public string Message { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Whether the user has read this reply. Only relevant for admin replies.
    /// </summary>
    public bool IsRead { get; set; } = false;

    [JsonIgnore]
    [ForeignKey(nameof(SupportRequestId))]
    public SupportRequest? SupportRequest { get; set; }

    [JsonIgnore]
    [ForeignKey(nameof(UserId))]
    public User? User { get; set; }
}
