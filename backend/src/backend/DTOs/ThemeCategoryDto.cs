using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class ThemeCategoryDto
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? ParentName { get; set; }
    public int SortOrder { get; set; }

    public static ThemeCategoryDto FromEntity(CollectionThemeCategory category)
    {
        return new ThemeCategoryDto
        {
            Name = category.Name,
            Description = category.Description,
            ParentName = category.ParentName,
            SortOrder = category.SortOrder
        };
    }
}