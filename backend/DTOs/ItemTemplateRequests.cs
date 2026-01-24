using System.ComponentModel.DataAnnotations;
using backend.Models;

namespace backend.DTOs;

public class ItemTemplatePropertyDto
{
    [Required]
    [MaxLength(100)]
    public string Category { get; set; } = string.Empty;

    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = string.Empty;
}

public class CreateItemTemplateRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string Description { get; set; } = string.Empty;

    public List<ItemTemplatePropertyDto> Properties { get; set; } = new();

    public ItemTemplate ToItemTemplate(int tenantId)
    {
        var template = new ItemTemplate
        {
            TenantId = tenantId,
            Name = Name,
            Description = Description
        };

        var sortOrder = 0;
        foreach (var prop in Properties)
        {
            template.Properties.Add(new ItemTemplateProperty
            {
                Category = prop.Category,
                Name = prop.Name,
                SortOrder = sortOrder++
            });
        }

        return template;
    }
}

public class UpdateItemTemplateRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string Description { get; set; } = string.Empty;

    public List<ItemTemplatePropertyDto> Properties { get; set; } = new();

    public ItemTemplate ToItemTemplate()
    {
        var template = new ItemTemplate
        {
            Name = Name,
            Description = Description
        };

        foreach (var prop in Properties)
        {
            template.Properties.Add(new ItemTemplateProperty
            {
                Category = prop.Category,
                Name = prop.Name
            });
        }

        return template;
    }
}

public class ItemTemplateResponse
{
    public int ItemTemplateId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool IsShared { get; set; }
    public bool IsEditable { get; set; }
    public List<ItemTemplatePropertyResponse> Properties { get; set; } = new();
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }

    public static ItemTemplateResponse FromItemTemplate(ItemTemplate template, int currentTenantId)
    {
        return new ItemTemplateResponse
        {
            ItemTemplateId = template.Id,
            Name = template.Name,
            Description = template.Description,
            IsShared = template.TenantId == null,
            IsEditable = template.TenantId == currentTenantId, // Only tenant-owned templates are editable
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

public class ItemTemplatePropertyResponse
{
    public int ItemTemplatePropertyId { get; set; }
    public string Category { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
}
