using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace OneBigHead.Server.Models;

public class SupportRequest
{
    [Key]
    [JsonPropertyName("supportRequestId")]
    public int Id { get; set; }

    /// <summary>
    /// The user who submitted the request. Null for anonymous requests.
    /// </summary>
    public int? UserId { get; set; }

    /// <summary>
    /// Email address for notifications. Required for all requests.
    /// For logged-in users, this is auto-populated from their account.
    /// </summary>
    [Required]
    [MaxLength(320)]
    public string Email { get; set; } = string.Empty;

    [Required]
    [MaxLength(200)]
    public string Subject { get; set; } = string.Empty;

    [Required]
    [MaxLength(4000)]
    public string Description { get; set; } = string.Empty;

    public SupportRequestStatus Status { get; set; } = SupportRequestStatus.Open;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Soft delete flag. Deleted requests are not permanently removed.
    /// </summary>
    public bool IsDeleted { get; set; } = false;

    public DateTime? DeletedAt { get; set; }

    [JsonIgnore]
    [ForeignKey(nameof(UserId))]
    public User? User { get; set; }

    public ICollection<SupportReply> Replies { get; set; } = new List<SupportReply>();
}
