using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Items;

/// <summary>Workspace-scoped item editing, independent of HTTP response handling.</summary>
public interface IItemWriteService
{
    Task<ItemWriteResult> CreateAsync(int workspaceId, CreateItemRequest request);
    Task<ItemWriteResult> UpdateAsync(int workspaceId, int id, UpdateItemRequest request);
    Task<bool> DeleteAsync(int workspaceId, int id);
}
