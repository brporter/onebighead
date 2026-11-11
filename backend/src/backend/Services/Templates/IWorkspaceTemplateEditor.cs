using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Templates;

public interface IWorkspaceTemplateEditor
{
    Task<ItemTemplate> CreateAsync(int workspaceId, CreateItemTemplateRequest request);
    Task<ItemTemplate?> UpdateAsync(int workspaceId, int id, UpdateItemTemplateRequest request);
    Task<bool> DeleteAsync(int workspaceId, int id);
}
