using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace backend.Models;

public class CategoryItemTemplate
{
    public int CategoryId { get; set; }

    public int ItemTemplateId { get; set; }

    public int SortOrder { get; set; } = 0;

    [JsonIgnore]
    [ForeignKey(nameof(CategoryId))]
    public Category? Category { get; set; }

    [JsonIgnore]
    [ForeignKey(nameof(ItemTemplateId))]
    public ItemTemplate? ItemTemplate { get; set; }
}
