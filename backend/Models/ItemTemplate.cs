using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace OneBigHead.Server.Models;

public class ItemTemplate
{
    [Key]
    [JsonPropertyName("itemTemplateId")]
    public int Id { get; set; }

    /// <summary>
    /// Null for shared/system templates (available to all workspaces, read-only).
    /// Set for workspace-owned templates (editable by workspace users).
    /// </summary>
    public int? WorkspaceId { get; set; }

    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string Description { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    [JsonIgnore]
    [ForeignKey(nameof(WorkspaceId))]
    public Workspace? Workspace { get; set; }

    public ICollection<ItemTemplateProperty> Properties { get; set; } = new List<ItemTemplateProperty>();

    [JsonIgnore]
    public ICollection<CollectionItemTemplate> CollectionItemTemplates { get; set; } = new List<CollectionItemTemplate>();

    [JsonIgnore]
    public ICollection<CategoryItemTemplate> CategoryItemTemplates { get; set; } = new List<CategoryItemTemplate>();
}
