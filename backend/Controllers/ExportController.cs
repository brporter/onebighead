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

    public ExportController(
        ICollectionRepository collectionRepository,
        ICategoryRepository categoryRepository,
        IItemRepository itemRepository)
    {
        _collectionRepository = collectionRepository;
        _categoryRepository = categoryRepository;
        _itemRepository = itemRepository;
    }

    [HttpGet]
    public async Task<IActionResult> ExportData()
    {
        var tenantId = GetTenantId();

        var collections = await _collectionRepository.GetAllAsync(tenantId);
        var categories = await _categoryRepository.GetAllAsync(tenantId);
        var items = await _itemRepository.GetAllAsync(tenantId);

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
                Properties = i.Properties,
                Images = i.Images
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
