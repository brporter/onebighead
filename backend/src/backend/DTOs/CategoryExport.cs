using System.Text.Json.Serialization;

namespace OneBigHead.Server.DTOs;

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