using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Items;

/// <summary>Workspace-scoped item projections, ordered by ID for stable pagination.</summary>
public interface IItemReadService
{
    Task<IReadOnlyList<Item>> GetAllAsync(int workspaceId, int? categoryId = null, bool includeDescendants = false);
    Task<Item?> GetByIdAsync(int id, int workspaceId);
}
