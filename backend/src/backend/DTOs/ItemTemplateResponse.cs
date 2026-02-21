using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class ItemTemplateResponse
{
    public int ItemTemplateId { get; set; }
    public Guid TemplateKey { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool IsSystem { get; set; }
    public List<ItemTemplatePropertyResponse> Properties { get; set; } = new();
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }

    public static ItemTemplateResponse FromItemTemplate(ItemTemplate template)
    {
        return new ItemTemplateResponse
        {
            ItemTemplateId = template.Id,
            TemplateKey = template.TemplateKey,
            Name = template.Name,
            Description = template.Description,
            IsSystem = template.WorkspaceId == null,
            Properties = template.Properties
                .OrderBy(p => p.SortOrder)
                .Select(p => new ItemTemplatePropertyResponse
                {
                    ItemTemplatePropertyId = p.Id,
                    Category = p.Category,
                    Name = p.Name
                })
                .ToList(),
            CreatedAt = template.CreatedAt,
            UpdatedAt = template.UpdatedAt
        };
    }
}