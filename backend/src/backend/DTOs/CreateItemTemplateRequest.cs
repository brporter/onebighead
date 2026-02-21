using System.ComponentModel.DataAnnotations;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class CreateItemTemplateRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string Description { get; set; } = string.Empty;

    public List<ItemTemplatePropertyDto> Properties { get; set; } = new();

    public ItemTemplate ToItemTemplate(int workspaceId)
    {
        var template = new ItemTemplate
        {
            WorkspaceId = workspaceId,
            TemplateKey = ItemTemplate.GenerateTemplateKey(),
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