using System.Text.Json.Serialization;

namespace api.Models;

public record Category(
    [property: JsonPropertyName("categoryId")] int Id,
    int TenantId,
    string Name,
    string Description,
    int? ParentCategoryId = null);

