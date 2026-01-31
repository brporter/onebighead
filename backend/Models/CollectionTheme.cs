using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace OneBigHead.Server.Models;

/// <summary>
/// A collection theme provides a preset bundle of templates and categories
/// that users can apply when creating a new collection.
/// </summary>
public class CollectionTheme
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(500)]
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Icon identifier (e.g., 'book', 'gamepad', 'palette') for UI display.
    /// </summary>
    [MaxLength(50)]
    public string IconName { get; set; } = string.Empty;

    public int SortOrder { get; set; } = 0;

    [JsonIgnore]
    public ICollection<CollectionThemeTemplate> ThemeTemplates { get; set; } = new List<CollectionThemeTemplate>();

    [JsonIgnore]
    public ICollection<CollectionThemeCategory> ThemeCategories { get; set; } = new List<CollectionThemeCategory>();
}
