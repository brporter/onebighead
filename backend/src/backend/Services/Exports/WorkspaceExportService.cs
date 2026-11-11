using System.IO.Compression;
using System.Text.Json;
using System.Globalization;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Exports;

public sealed class WorkspaceExportService(
    ICollectionRepository _collectionRepository,
    ICategoryRepository _categoryRepository,
    IItemRepository _itemRepository,
    IItemTemplateRepository _itemTemplateRepository,
    TimeProvider clock) : IWorkspaceExportService
{
    public async Task<WorkspaceExport> ExportAsync(int workspaceId)
    {
        var collections = await _collectionRepository.GetAllAsync(workspaceId);
        var categories = await _categoryRepository.GetAllAsync(workspaceId);
        var items = await _itemRepository.GetAllAsync(workspaceId);
        var itemTemplates = await _itemTemplateRepository.GetWorkspaceTemplatesAsync(workspaceId);

        var exportData = new ExportData
        {
            ExportedAt = clock.GetUtcNow().UtcDateTime,
            Collections = collections.Select(c => new CollectionExport
            {
                CollectionId = c.Id,
                Name = c.Name,
                Description = c.Description,
                HeroImageUrl = c.HeroImageUrl,
                Slug = c.Slug,
                CreatedAt = c.CreatedAt
            }).ToList(),
            Categories = categories.Select(c => new CategoryExport
            {
                CategoryId = c.Id,
                CollectionId = c.CollectionId,
                Name = c.Name,
                Description = c.Description,
                IsSystem = c.IsSystem,
                ParentCategoryId = c.ParentCategoryId
            }).ToList(),
            Items = items.Select(i => new ItemExport
            {
                Id = i.Id,
                CollectionId = i.CollectionId,
                CategoryId = i.CategoryId,
                Name = i.Name,
                Summary = i.Summary,
                Description = i.Description,
                UserFlag = i.UserFlag,
                Properties = i.Properties,
                Images = i.Images
            }).ToList(),
            ItemTemplates = itemTemplates.Select(t => new ItemTemplateExport
            {
                ItemTemplateId = t.Id,
                Name = t.Name,
                Description = t.Description,
                Properties = t.Properties.Select(p => new ItemTemplatePropertyExport
                {
                    Category = p.Category,
                    Name = p.Name,
                    SortOrder = p.SortOrder
                }).ToList()
            }).ToList()
        };

        var jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
        var json = JsonSerializer.Serialize(exportData, jsonOptions);

        var memoryStream = new MemoryStream();
        using (var archive = new ZipArchive(memoryStream, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = archive.CreateEntry("export.json", CompressionLevel.Optimal);
            using var entryStream = entry.Open();
            using var writer = new StreamWriter(entryStream);
            await writer.WriteAsync(json);
        }

        memoryStream.Position = 0;

        var timestamp = exportData.ExportedAt.ToString("yyyy-MM-dd-HHmmss", CultureInfo.InvariantCulture);
        return new(memoryStream, $"onebighead-export-{timestamp}.zip");
    }
}
