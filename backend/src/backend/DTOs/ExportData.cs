using System.Text.Json.Serialization;

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

    [JsonPropertyName("itemTemplates")]
    public List<ItemTemplateExport> ItemTemplates { get; set; } = new();
}