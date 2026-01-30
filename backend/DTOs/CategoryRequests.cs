using System.ComponentModel.DataAnnotations;
using backend.Models;

namespace backend.DTOs;

public class CreateCategoryRequest
{
    public int CollectionId { get; set; }

    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string? Description { get; set; }
    public int? ParentCategoryId { get; set; }
    public bool? IsPublicOverride { get; set; }
    public List<int>? ItemTemplateIds { get; set; }
}

public class UpdateCategoryRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string? Description { get; set; }
    public int? ParentCategoryId { get; set; }
    public bool? IsPublicOverride { get; set; }
    public List<int>? ItemTemplateIds { get; set; }
}

public class CategoryResponse
{
    public int CategoryId { get; set; }
    public int TenantId { get; set; }
    public int CollectionId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool IsSystem { get; set; }
    public int? ParentCategoryId { get; set; }
    public bool? IsPublicOverride { get; set; }
    public bool EffectiveIsPublic { get; set; }
    public List<int> ItemTemplateIds { get; set; } = new();

    public static CategoryResponse FromCategory(Category category, List<int>? templateIds = null)
    {
        return new CategoryResponse
        {
            CategoryId = category.Id,
            TenantId = category.TenantId,
            CollectionId = category.CollectionId,
            Name = category.Name,
            Description = category.Description,
            IsSystem = category.IsSystem,
            ParentCategoryId = category.ParentCategoryId,
            IsPublicOverride = category.IsPublicOverride,
            EffectiveIsPublic = category.EffectiveIsPublic,
            ItemTemplateIds = templateIds ?? new()
        };
    }
}
