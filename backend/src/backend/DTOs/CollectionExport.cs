using System.Text.Json.Serialization;

namespace OneBigHead.Server.DTOs;

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