using System.ComponentModel.DataAnnotations;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

/// <summary>
/// Base class for item request DTOs with shared properties.
/// </summary>
public abstract class ItemRequestBase
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

    /// <summary>
    /// The template key of the item template this item was created from.
    /// Null if the item was created from scratch without a template.
    /// </summary>
    public Guid? TemplateKey { get; set; }

    public List<ItemProperty> Properties { get; set; } = new();

    public List<ItemImage> Images { get; set; } = new();

    public Visibility Visibility { get; set; } = Visibility.Default;

    public UserFlag UserFlag { get; set; } = UserFlag.None;

    /// <summary>
    /// Populates the shared properties on an Item entity.
    /// </summary>
    protected void PopulateItem(Item item)
    {
        item.CollectionId = CollectionId;
        item.CategoryId = CategoryId;
        item.TemplateKey = TemplateKey;
        item.Name = Name;
        item.Summary = Summary;
        item.Description = Description;
        item.Properties = Properties;
        item.Images = Images;
        item.Visibility = Visibility;
        item.UserFlag = UserFlag;
    }
}

public class CreateItemRequest : ItemRequestBase
{
    public Item ToItem(int workspaceId)
    {
        var item = new Item { WorkspaceId = workspaceId };
        PopulateItem(item);
        return item;
    }
}

public class UpdateItemRequest : ItemRequestBase
{
    public Item ToItem(int id, int workspaceId)
    {
        var item = new Item { Id = id, WorkspaceId = workspaceId };
        PopulateItem(item);
        return item;
    }
}
