using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace backend.Models;

/// <summary>
/// Defines a category template within a collection theme.
/// When a theme is applied, these become actual categories in the new collection.
/// </summary>
public class CollectionThemeCategory
{
    [Key]
    public int Id { get; set; }

    public int ThemeId { get; set; }

    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// References another category by name within the same theme to establish hierarchy.
    /// Null means this is a root-level category.
    /// </summary>
    [MaxLength(200)]
    public string? ParentName { get; set; }

    public int SortOrder { get; set; } = 0;

    [JsonIgnore]
    [ForeignKey(nameof(ThemeId))]
    public CollectionTheme? Theme { get; set; }
}
