using System.ComponentModel.DataAnnotations;
using backend.Models;

namespace backend.DTOs;

public class CreateItemRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(500)]
    public string Summary { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public int CollectionId { get; set; }

    public int? CategoryId { get; set; }

    public List<ItemProperty> Properties { get; set; } = new();

    public List<ItemImage> Images { get; set; } = new();

    public bool? IsPublicOverride { get; set; }

    public UserFlag UserFlag { get; set; } = UserFlag.None;

    public Item ToItem(int tenantId)
    {
        return new Item
        {
            TenantId = tenantId,
            CollectionId = CollectionId,
            CategoryId = CategoryId,
            Name = Name,
            Summary = Summary,
            Description = Description,
            Properties = Properties,
            Images = Images,
            IsPublicOverride = IsPublicOverride,
            UserFlag = UserFlag
        };
    }
}

public class UpdateItemRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(500)]
    public string Summary { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public int CollectionId { get; set; }

    public int? CategoryId { get; set; }

    public List<ItemProperty> Properties { get; set; } = new();

    public List<ItemImage> Images { get; set; } = new();

    public bool? IsPublicOverride { get; set; }

    public UserFlag UserFlag { get; set; } = UserFlag.None;

    public Item ToItem(int id, int tenantId)
    {
        return new Item
        {
            Id = id,
            TenantId = tenantId,
            CollectionId = CollectionId,
            CategoryId = CategoryId,
            Name = Name,
            Summary = Summary,
            Description = Description,
            Properties = Properties,
            Images = Images,
            IsPublicOverride = IsPublicOverride,
            UserFlag = UserFlag
        };
    }
}
