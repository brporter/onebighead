using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IO.Compression;
using System.Text.Json;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ExportController : ApiControllerBase
{
    private readonly ICollectionRepository _collectionRepository;
    private readonly ICategoryRepository _categoryRepository;
    private readonly IItemRepository _itemRepository;
    private readonly IItemTemplateRepository _itemTemplateRepository;

    public ExportController(
        ICollectionRepository collectionRepository,
        ICategoryRepository categoryRepository,
        IItemRepository itemRepository,
        IItemTemplateRepository itemTemplateRepository)
    {
        _collectionRepository = collectionRepository;
        _categoryRepository = categoryRepository;
        _itemRepository = itemRepository;
        _itemTemplateRepository = itemTemplateRepository;
    }

    [HttpGet]
    [Authorize(Policy = "TenantAdmin")]
    public async Task<IActionResult> ExportData()
    {
        var tenantId = GetTenantId();

        var collections = await _collectionRepository.GetAllAsync(tenantId);
        var categories = await _categoryRepository.GetAllAsync(tenantId);
        var items = await _itemRepository.GetAllAsync(tenantId);
        var itemTemplates = await _itemTemplateRepository.GetTenantTemplatesAsync(tenantId);

        var exportData = new ExportData
        {
            ExportedAt = DateTime.UtcNow,
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

        var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd-HHmmss");
        return File(memoryStream, "application/zip", $"onebighead-export-{timestamp}.zip");
    }
}
