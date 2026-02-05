using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace OneBigHead.Server.Models;

public class Collection
{
    [Key]
    [JsonPropertyName("collectionId")]
    public int Id { get; set; }

    public int WorkspaceId { get; set; }

    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string Description { get; set; } = string.Empty;

    [MaxLength(2000)]
    public string? HeroImageUrl { get; set; }

    [Required]
    [MaxLength(100)]
    public string Slug { get; set; } = string.Empty;

    [JsonPropertyName("visibility")]
    public Visibility Visibility { get; set; } = Visibility.Private;

    [NotMapped]
    [JsonPropertyName("effectiveIsPublic")]
    public bool EffectiveIsPublic => Visibility == Visibility.Public;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [JsonIgnore]
    [ForeignKey(nameof(WorkspaceId))]
    public Workspace? Workspace { get; set; }

    [JsonIgnore]
    public ICollection<Category> Categories { get; set; } = new List<Category>();

    [JsonIgnore]
    public ICollection<Item> Items { get; set; } = new List<Item>();

    [JsonIgnore]
    public ICollection<CollectionItemTemplate> CollectionItemTemplates { get; set; } = new List<CollectionItemTemplate>();
}
