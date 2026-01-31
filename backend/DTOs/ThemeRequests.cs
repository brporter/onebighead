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

public class ThemeTemplateDto
{
    public int ItemTemplateId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public List<ItemTemplatePropertyDto> Properties { get; set; } = new();

    public static ThemeTemplateDto FromEntity(CollectionThemeTemplate themeTemplate)
    {
        var template = themeTemplate.ItemTemplate;
        return new ThemeTemplateDto
        {
            ItemTemplateId = template?.Id ?? 0,
            Name = template?.Name ?? string.Empty,
            Description = template?.Description ?? string.Empty,
            Properties = template?.Properties
                .OrderBy(p => p.SortOrder)
                .Select(p => new ItemTemplatePropertyDto
                {
                    Category = p.Category,
                    Name = p.Name
                })
                .ToList() ?? new()
        };
    }
}

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
