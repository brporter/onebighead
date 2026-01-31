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
    /// Null for shared/system templates (available to all tenants, read-only).
    /// Set for tenant-owned templates (editable by tenant users).
    /// </summary>
    public int? TenantId { get; set; }

    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string Description { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    [JsonIgnore]
    [ForeignKey(nameof(TenantId))]
    public Tenant? Tenant { get; set; }

    public ICollection<ItemTemplateProperty> Properties { get; set; } = new List<ItemTemplateProperty>();

    [JsonIgnore]
    public ICollection<CollectionItemTemplate> CollectionItemTemplates { get; set; } = new List<CollectionItemTemplate>();

    [JsonIgnore]
    public ICollection<CategoryItemTemplate> CategoryItemTemplates { get; set; } = new List<CategoryItemTemplate>();
}
