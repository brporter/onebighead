using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace OneBigHead.Server.Models;

public class Item
{
    [Key]
    [JsonPropertyName("id")]
    public int? Id { get; set; }

    [JsonPropertyName("workspaceId")]
    public int WorkspaceId { get; set; }

    [JsonPropertyName("collectionId")]
    public int CollectionId { get; set; }

    [JsonPropertyName("categoryId")]
    public int? CategoryId { get; set; }

    /// <summary>
    /// The template key of the item template this item was created from.
    /// Null if the item was created from scratch without a template.
    /// This is not a foreign key - it's a soft reference that survives template deletion.
    /// </summary>
    [JsonPropertyName("templateKey")]
    public Guid? TemplateKey { get; set; }

    [Required]
    [MaxLength(200)]
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [MaxLength(500)]
    [JsonPropertyName("summary")]
    public string Summary { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("properties")]
    public List<ItemProperty> Properties { get; set; } = new();

    [JsonPropertyName("images")]
    public List<ItemImage> Images { get; set; } = new();

    [JsonPropertyName("visibility")]
    public Visibility Visibility { get; set; } = Visibility.Default;

    [NotMapped]
    [JsonPropertyName("effectiveIsPublic")]
    public bool EffectiveIsPublic { get; set; }

    /// <summary>
    /// User's relationship with this item (Have, Want, Trade/Sell).
    /// </summary>
    [JsonPropertyName("userFlag")]
    public UserFlag UserFlag { get; set; } = UserFlag.Have;

    [JsonIgnore]
    [ForeignKey(nameof(WorkspaceId))]
    public Workspace? Workspace { get; set; }

    [JsonIgnore]
    [ForeignKey(nameof(CollectionId))]
    public Collection? Collection { get; set; }

    [JsonIgnore]
    [ForeignKey(nameof(CategoryId))]
    public Category? Category { get; set; }
}
