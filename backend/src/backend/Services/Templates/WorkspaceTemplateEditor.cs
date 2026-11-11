using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Templates;

public sealed class WorkspaceTemplateEditor(IItemTemplateRepository templates) : IWorkspaceTemplateEditor
{
    public Task<ItemTemplate> CreateAsync(int workspaceId, CreateItemTemplateRequest request) =>
        templates.CreateAsync(request.ToItemTemplate(workspaceId));

    public async Task<ItemTemplate?> UpdateAsync(int workspaceId, int id, UpdateItemTemplateRequest request)
    {
        var existing = await templates.GetByIdAsync(id, workspaceId);
        if (existing is null) return null;
        var template = request.ToItemTemplate();
        return existing.WorkspaceId is null
            ? await templates.CopySystemTemplateAsync(id, workspaceId, template)
            : await templates.UpdateAsync(id, template, workspaceId);
    }

    public Task<bool> DeleteAsync(int workspaceId, int id) => templates.DeleteAsync(id, workspaceId);
}
