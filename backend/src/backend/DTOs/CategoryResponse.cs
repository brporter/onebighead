using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class CategoryResponse
{
    public int CategoryId { get; set; }
    public int WorkspaceId { get; set; }
    public int CollectionId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool IsSystem { get; set; }
    public int? ParentCategoryId { get; set; }
    public Visibility Visibility { get; set; } = Visibility.Private;
    public bool EffectiveIsPublic { get; set; }
    public List<int> ItemTemplateIds { get; set; } = new();

    public static CategoryResponse FromCategory(Category category, List<int>? templateIds = null)
    {
        return new CategoryResponse
        {
            CategoryId = category.Id,
            WorkspaceId = category.WorkspaceId,
            CollectionId = category.CollectionId,
            Name = category.Name,
            Description = category.Description,
            IsSystem = category.IsSystem,
            ParentCategoryId = category.ParentCategoryId,
            Visibility = category.Visibility,
            EffectiveIsPublic = category.EffectiveIsPublic,
            ItemTemplateIds = templateIds ?? new()
        };
    }
}