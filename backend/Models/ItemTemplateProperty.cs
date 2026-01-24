using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace backend.Models;

public class ItemTemplateProperty
{
    [Key]
    [JsonPropertyName("itemTemplatePropertyId")]
    public int Id { get; set; }

    public int ItemTemplateId { get; set; }

    [Required]
    [MaxLength(100)]
    public string Category { get; set; } = string.Empty;

    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = string.Empty;

    public int SortOrder { get; set; }

    [JsonIgnore]
    [ForeignKey(nameof(ItemTemplateId))]
    public ItemTemplate? ItemTemplate { get; set; }
}
