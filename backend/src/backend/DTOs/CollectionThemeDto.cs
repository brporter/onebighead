using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class CollectionThemeDto
{
    public int ThemeId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string IconName { get; set; } = string.Empty;
    public int SortOrder { get; set; }
    public List<ThemeTemplateDto> Templates { get; set; } = new();
    public List<ThemeCategoryDto> Categories { get; set; } = new();

    public static CollectionThemeDto FromEntity(CollectionTheme theme)
    {
        return new CollectionThemeDto
        {
            ThemeId = theme.Id,
            Name = theme.Name,
            Description = theme.Description,
            IconName = theme.IconName,
            SortOrder = theme.SortOrder,
            Templates = theme.ThemeTemplates
                .OrderBy(t => t.SortOrder)
                .Select(ThemeTemplateDto.FromEntity)
                .ToList(),
            Categories = theme.ThemeCategories
                .OrderBy(c => c.SortOrder)
                .Select(ThemeCategoryDto.FromEntity)
                .ToList()
        };
    }
}