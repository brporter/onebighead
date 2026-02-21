using System.Text.Json.Serialization;

namespace OneBigHead.Server.DTOs;

public class ItemTemplateExport
{
    [JsonPropertyName("itemTemplateId")]
    public int ItemTemplateId { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("properties")]
    public List<ItemTemplatePropertyExport> Properties { get; set; } = new();
}