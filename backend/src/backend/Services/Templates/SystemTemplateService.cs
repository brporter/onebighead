using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Templates;

/** Owns shared template definitions; existing items keep their values and origin keys. */
public sealed class SystemTemplateService(IDbContextFactory<AppDbContext> contextFactory, TimeProvider time)
    : ISystemTemplateService
{
    public async Task<IReadOnlyList<ItemTemplateResponse>> GetAllAsync()
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        var templates = await context.ItemTemplates.AsNoTracking().Include(t => t.Properties)
            .Where(t => t.WorkspaceId == null).OrderBy(t => t.Name).ToListAsync();
        return templates.Select(ItemTemplateResponse.FromItemTemplate).ToList();
    }

    public async Task<ItemTemplateResponse?> GetAsync(int id)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        var template = await context.ItemTemplates.AsNoTracking().Include(t => t.Properties)
            .SingleOrDefaultAsync(t => t.Id == id && t.WorkspaceId == null);
        return template is null ? null : ItemTemplateResponse.FromItemTemplate(template);
    }

    public async Task<ItemTemplateResponse> CreateAsync(SystemTemplateRequest request)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        var template = new ItemTemplate { TemplateKey = ItemTemplate.GenerateTemplateKey(), CreatedAt = time.GetUtcNow().UtcDateTime };
        ApplyDefinition(template, request);
        context.ItemTemplates.Add(template);
        await context.SaveChangesAsync();
        return ItemTemplateResponse.FromItemTemplate(template);
    }

    public async Task<ItemTemplateResponse?> UpdateAsync(int id, SystemTemplateRequest request)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        var template = await context.ItemTemplates.Include(t => t.Properties)
            .SingleOrDefaultAsync(t => t.Id == id && t.WorkspaceId == null);
        if (template is null) return null;
        context.ItemTemplateProperties.RemoveRange(template.Properties);
        ApplyDefinition(template, request);
        await context.SaveChangesAsync();
        return ItemTemplateResponse.FromItemTemplate(template);
    }

    public async Task<bool> DeleteAsync(int id)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        var template = await context.ItemTemplates
            .Include(t => t.CollectionItemTemplates).Include(t => t.CategoryItemTemplates)
            .SingleOrDefaultAsync(t => t.Id == id && t.WorkspaceId == null);
        if (template is null) return false;

        // These relationships use restrictive foreign keys. Remove assignments
        // and the definition in one SaveChanges transaction; item data survives.
        context.CollectionItemTemplates.RemoveRange(template.CollectionItemTemplates);
        context.CategoryItemTemplates.RemoveRange(template.CategoryItemTemplates);
        context.ItemTemplates.Remove(template);
        await context.SaveChangesAsync();
        return true;
    }

    private void ApplyDefinition(ItemTemplate template, SystemTemplateRequest request)
    {
        template.Name = request.Name;
        template.Description = request.Description;
        template.UpdatedAt = time.GetUtcNow().UtcDateTime;
        template.Properties = request.Properties.Select((property, index) => new ItemTemplateProperty
        { Category = property.Category, Name = property.Name, SortOrder = index }).ToList();
    }
}
