using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace OneBigHead.Server.Models;

/// <summary>
/// Links a collection theme to an item template.
/// When a theme is applied, these templates are associated with the new collection.
/// </summary>
public class CollectionThemeTemplate
{
    public int ThemeId { get; set; }

    public int ItemTemplateId { get; set; }

    public int SortOrder { get; set; } = 0;

    [JsonIgnore]
    [ForeignKey(nameof(ThemeId))]
    public CollectionTheme? Theme { get; set; }

    [JsonIgnore]
    [ForeignKey(nameof(ItemTemplateId))]
    public ItemTemplate? ItemTemplate { get; set; }
}
