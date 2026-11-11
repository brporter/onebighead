using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Categories;

/// <summary>Workspace-scoped category projections. Null means the requested resource is absent.</summary>
public interface ICategoryReadService
{
    Task<IReadOnlyList<CategoryResponse>?> GetAllAsync(int workspaceId, int? collectionId = null);
    Task<CategoryResponse?> GetByIdAsync(int categoryId, int workspaceId);
    Task<IReadOnlyList<int>?> GetInheritedTemplateIdsAsync(int categoryId, int workspaceId);
}
