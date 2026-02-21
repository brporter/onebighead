using System.Text.Json.Serialization;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

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

    [JsonPropertyName("userFlag")]
    public UserFlag UserFlag { get; set; } = UserFlag.Have;

    [JsonPropertyName("properties")]
    public List<ItemProperty> Properties { get; set; } = new();

    [JsonPropertyName("images")]
    public List<ItemImage> Images { get; set; } = new();
}