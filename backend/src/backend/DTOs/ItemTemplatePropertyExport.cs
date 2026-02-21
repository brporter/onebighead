using System.Text.Json.Serialization;

namespace OneBigHead.Server.DTOs;

public class ItemTemplatePropertyExport
{
    [JsonPropertyName("category")]
    public string Category { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("sortOrder")]
    public int SortOrder { get; set; }
}