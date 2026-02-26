using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.Models;

public class ItemEmbedding
{
    [Key]
    public int Id { get; set; }
    public int ItemId { get; set; }
    public int WorkspaceId { get; set; }
    /// <summary>
    /// 1536-dimensional vector stored as JSON float array.
    /// </summary>
    public float[] Vector { get; set; } = Array.Empty<float>();
    /// <summary>
    /// SHA256 hash of (Name+Summary+Description+Properties) to detect staleness.
    /// </summary>
    [MaxLength(64)]
    public string ContentHash { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
