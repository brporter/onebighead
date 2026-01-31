using System.Text.Json.Serialization;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class ExportData
{
    [JsonPropertyName("exportedAt")]
    public DateTime ExportedAt { get; set; }

    [JsonPropertyName("collections")]
    public List<CollectionExport> Collections { get; set; } = new();

    [JsonPropertyName("categories")]
    public List<CategoryExport> Categories { get; set; } = new();

    [JsonPropertyName("items")]
    public List<ItemExport> Items { get; set; } = new();
}

public class CollectionExport
{
    [JsonPropertyName("collectionId")]
    public int CollectionId { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("heroImageUrl")]
    public string? HeroImageUrl { get; set; }

    [JsonPropertyName("slug")]
    public string Slug { get; set; } = string.Empty;

    [JsonPropertyName("createdAt")]
    public DateTime CreatedAt { get; set; }
}

public class CategoryExport
{
    [JsonPropertyName("categoryId")]
    public int CategoryId { get; set; }

    [JsonPropertyName("collectionId")]
    public int CollectionId { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("isSystem")]
    public bool IsSystem { get; set; }

    [JsonPropertyName("parentCategoryId")]
    public int? ParentCategoryId { get; set; }
}

public class ItemExport
{
    [JsonPropertyName("id")]
    public int? Id { get; set; }

    [JsonPropertyName("collectionId")]
    public int CollectionId { get; set; }

    [JsonPropertyName("categoryId")]
    public int? CategoryId { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("summary")]
    public string Summary { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("properties")]
    public List<ItemProperty> Properties { get; set; } = new();

    [JsonPropertyName("images")]
    public List<ItemImage> Images { get; set; } = new();
}
