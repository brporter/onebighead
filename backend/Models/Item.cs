using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace backend.Models;

public record ItemProperty(string Category, string Name, string Value);

public record ItemImage(string Url, string Alt);

public class Item
{
    [Key]
    [JsonPropertyName("id")]
    public int? Id { get; set; }

    [JsonPropertyName("tenantId")]
    public int TenantId { get; set; }

    [JsonPropertyName("categoryId")]
    public int? CategoryId { get; set; }

    [Required]
    [MaxLength(200)]
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [MaxLength(500)]
    [JsonPropertyName("summary")]
    public string Summary { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("properties")]
    public List<ItemProperty> Properties { get; set; } = new();

    [JsonPropertyName("images")]
    public List<ItemImage> Images { get; set; } = new();

    [JsonIgnore]
    [ForeignKey(nameof(TenantId))]
    public Tenant? Tenant { get; set; }

    [JsonIgnore]
    [ForeignKey(nameof(CategoryId))]
    public Category? Category { get; set; }
}

