using System.ComponentModel.DataAnnotations;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class CreateItemRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(500)]
    public string Summary { get; set; } = string.Empty;

    [MaxLength(10000)]
    public string Description { get; set; } = string.Empty;

    public int CollectionId { get; set; }

    public int? CategoryId { get; set; }

    public List<ItemProperty> Properties { get; set; } = new();

    public List<ItemImage> Images { get; set; } = new();

    public Visibility Visibility { get; set; } = Visibility.Default;

    public UserFlag UserFlag { get; set; } = UserFlag.None;

    public Item ToItem(int workspaceId)
    {
        return new Item
        {
            WorkspaceId = workspaceId,
            CollectionId = CollectionId,
            CategoryId = CategoryId,
            Name = Name,
            Summary = Summary,
            Description = Description,
            Properties = Properties,
            Images = Images,
            Visibility = Visibility,
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

    [MaxLength(10000)]
    public string Description { get; set; } = string.Empty;

    public int CollectionId { get; set; }

    public int? CategoryId { get; set; }

    public List<ItemProperty> Properties { get; set; } = new();

    public List<ItemImage> Images { get; set; } = new();

    public Visibility Visibility { get; set; } = Visibility.Default;

    public UserFlag UserFlag { get; set; } = UserFlag.None;

    public Item ToItem(int id, int workspaceId)
    {
        return new Item
        {
            Id = id,
            WorkspaceId = workspaceId,
            CollectionId = CollectionId,
            CategoryId = CategoryId,
            Name = Name,
            Summary = Summary,
            Description = Description,
            Properties = Properties,
            Images = Images,
            Visibility = Visibility,
            UserFlag = UserFlag
        };
    }
}
