using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

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