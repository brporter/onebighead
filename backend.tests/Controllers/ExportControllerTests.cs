using backend.Controllers;
using backend.Data;
using backend.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.IO.Compression;
using System.Security.Claims;
using System.Text.Json;

namespace backend.Tests.Controllers;

[Trait("Category", "Unit")]
public class ExportControllerTests
{
    private readonly Mock<ICollectionRepository> _mockCollectionRepository;
    private readonly Mock<ICategoryRepository> _mockCategoryRepository;
    private readonly Mock<IItemRepository> _mockItemRepository;
    private readonly ExportController _controller;
    private const int TestTenantId = 1;
    private const int TestUserId = 1;

    public ExportControllerTests()
    {
        _mockCollectionRepository = new Mock<ICollectionRepository>();
        _mockCategoryRepository = new Mock<ICategoryRepository>();
        _mockItemRepository = new Mock<IItemRepository>();
        _controller = new ExportController(
            _mockCollectionRepository.Object,
            _mockCategoryRepository.Object,
            _mockItemRepository.Object);

        var claims = new List<Claim>
        {
            new("tenant_id", TestTenantId.ToString()),
            new("sub", TestUserId.ToString()),
            new(ClaimTypes.NameIdentifier, "1"),
            new(ClaimTypes.Email, "test@example.com")
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var claimsPrincipal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = claimsPrincipal }
        };
    }

    #region ExportData Tests

    [Fact]
    public async Task ExportData_ReturnsFileResult_WithCorrectContentType()
    {
        // Arrange
        _mockCollectionRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Collection>());
        _mockCategoryRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Category>());
        _mockItemRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Item>());

        // Act
        var result = await _controller.ExportData();

        // Assert
        var fileResult = Assert.IsType<FileStreamResult>(result);
        Assert.Equal("application/zip", fileResult.ContentType);
        Assert.StartsWith("onebighead-export-", fileResult.FileDownloadName);
        Assert.EndsWith(".zip", fileResult.FileDownloadName);
    }

    [Fact]
    public async Task ExportData_ReturnsZipFile_ContainingExportJson()
    {
        // Arrange
        _mockCollectionRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Collection>());
        _mockCategoryRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Category>());
        _mockItemRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Item>());

        // Act
        var result = await _controller.ExportData();

        // Assert
        var fileResult = Assert.IsType<FileStreamResult>(result);
        var zipContents = await ReadStreamToByteArrayAsync(fileResult.FileStream);
        using var memoryStream = new MemoryStream(zipContents);
        using var archive = new ZipArchive(memoryStream, ZipArchiveMode.Read);

        var entry = archive.GetEntry("export.json");
        Assert.NotNull(entry);
    }

    [Fact]
    public async Task ExportData_ReturnsEmptyCollections_WhenNoData()
    {
        // Arrange
        _mockCollectionRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Collection>());
        _mockCategoryRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Category>());
        _mockItemRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Item>());

        // Act
        var result = await _controller.ExportData();

        // Assert
        var fileResult = Assert.IsType<FileStreamResult>(result);
        var exportData = await ExtractExportDataFromStream(fileResult.FileStream);

        Assert.Empty(exportData.Collections);
        Assert.Empty(exportData.Categories);
        Assert.Empty(exportData.Items);
    }

    [Fact]
    public async Task ExportData_IncludesAllCollections_WithCorrectData()
    {
        // Arrange
        var collections = new List<Collection>
        {
            new()
            {
                Id = 1,
                TenantId = TestTenantId,
                Name = "Collection 1",
                Description = "Description 1",
                HeroImageUrl = "https://example.com/image1.jpg",
                Slug = "collection-1",
                CreatedAt = new DateTime(2024, 1, 1, 12, 0, 0, DateTimeKind.Utc)
            },
            new()
            {
                Id = 2,
                TenantId = TestTenantId,
                Name = "Collection 2",
                Description = "Description 2",
                HeroImageUrl = null,
                Slug = "collection-2",
                CreatedAt = new DateTime(2024, 2, 1, 12, 0, 0, DateTimeKind.Utc)
            }
        };
        _mockCollectionRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(collections);
        _mockCategoryRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Category>());
        _mockItemRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Item>());

        // Act
        var result = await _controller.ExportData();

        // Assert
        var fileResult = Assert.IsType<FileStreamResult>(result);
        var exportData = await ExtractExportDataFromStream(fileResult.FileStream);

        Assert.Equal(2, exportData.Collections.Count);

        var collection1 = exportData.Collections.First(c => c.CollectionId == 1);
        Assert.Equal("Collection 1", collection1.Name);
        Assert.Equal("Description 1", collection1.Description);
        Assert.Equal("https://example.com/image1.jpg", collection1.HeroImageUrl);
        Assert.Equal("collection-1", collection1.Slug);

        var collection2 = exportData.Collections.First(c => c.CollectionId == 2);
        Assert.Equal("Collection 2", collection2.Name);
        Assert.Null(collection2.HeroImageUrl);
    }

    [Fact]
    public async Task ExportData_IncludesAllCategories_WithCorrectData()
    {
        // Arrange
        var categories = new List<Category>
        {
            new()
            {
                Id = 1,
                TenantId = TestTenantId,
                CollectionId = 1,
                Name = "Category 1",
                Description = "Category Description 1",
                IsSystem = true,
                ParentCategoryId = null
            },
            new()
            {
                Id = 2,
                TenantId = TestTenantId,
                CollectionId = 1,
                Name = "Category 2",
                Description = "Category Description 2",
                IsSystem = false,
                ParentCategoryId = 1
            }
        };
        _mockCollectionRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Collection>());
        _mockCategoryRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(categories);
        _mockItemRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Item>());

        // Act
        var result = await _controller.ExportData();

        // Assert
        var fileResult = Assert.IsType<FileStreamResult>(result);
        var exportData = await ExtractExportDataFromStream(fileResult.FileStream);

        Assert.Equal(2, exportData.Categories.Count);

        var category1 = exportData.Categories.First(c => c.CategoryId == 1);
        Assert.Equal("Category 1", category1.Name);
        Assert.Equal("Category Description 1", category1.Description);
        Assert.True(category1.IsSystem);
        Assert.Null(category1.ParentCategoryId);
        Assert.Equal(1, category1.CollectionId);

        var category2 = exportData.Categories.First(c => c.CategoryId == 2);
        Assert.Equal("Category 2", category2.Name);
        Assert.False(category2.IsSystem);
        Assert.Equal(1, category2.ParentCategoryId);
    }

    [Fact]
    public async Task ExportData_IncludesAllItems_WithCorrectData()
    {
        // Arrange
        var items = new List<Item>
        {
            new()
            {
                Id = 1,
                TenantId = TestTenantId,
                CollectionId = 1,
                CategoryId = 1,
                Name = "Item 1",
                Summary = "Summary 1",
                Description = "Description 1",
                Properties = new List<ItemProperty>
                {
                    new("Category1", "Property1", "Value1")
                },
                Images = new List<ItemImage>
                {
                    new("https://example.com/item1.jpg", "Alt 1")
                }
            },
            new()
            {
                Id = 2,
                TenantId = TestTenantId,
                CollectionId = 1,
                CategoryId = null,
                Name = "Item 2",
                Summary = "Summary 2",
                Description = "Description 2",
                Properties = new List<ItemProperty>(),
                Images = new List<ItemImage>()
            }
        };
        _mockCollectionRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Collection>());
        _mockCategoryRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Category>());
        _mockItemRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(items);

        // Act
        var result = await _controller.ExportData();

        // Assert
        var fileResult = Assert.IsType<FileStreamResult>(result);
        var exportData = await ExtractExportDataFromStream(fileResult.FileStream);

        Assert.Equal(2, exportData.Items.Count);

        var item1 = exportData.Items.First(i => i.Id == 1);
        Assert.Equal("Item 1", item1.Name);
        Assert.Equal("Summary 1", item1.Summary);
        Assert.Equal("Description 1", item1.Description);
        Assert.Equal(1, item1.CollectionId);
        Assert.Equal(1, item1.CategoryId);
        Assert.Single(item1.Properties);
        Assert.Equal("Property1", item1.Properties[0].Name);
        Assert.Single(item1.Images);
        Assert.Equal("https://example.com/item1.jpg", item1.Images[0].Url);

        var item2 = exportData.Items.First(i => i.Id == 2);
        Assert.Null(item2.CategoryId);
        Assert.Empty(item2.Properties);
        Assert.Empty(item2.Images);
    }

    [Fact]
    public async Task ExportData_UsesTenantIdFromClaims()
    {
        // Arrange
        _mockCollectionRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Collection>());
        _mockCategoryRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Category>());
        _mockItemRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Item>());

        // Act
        await _controller.ExportData();

        // Assert
        _mockCollectionRepository.Verify(repo => repo.GetAllAsync(TestTenantId), Times.Once);
        _mockCategoryRepository.Verify(repo => repo.GetAllAsync(TestTenantId), Times.Once);
        _mockItemRepository.Verify(repo => repo.GetAllAsync(TestTenantId), Times.Once);
    }

    [Fact]
    public async Task ExportData_IncludesExportedAtTimestamp()
    {
        // Arrange
        var beforeExport = DateTime.UtcNow;
        _mockCollectionRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Collection>());
        _mockCategoryRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Category>());
        _mockItemRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Item>());

        // Act
        var result = await _controller.ExportData();
        var afterExport = DateTime.UtcNow;

        // Assert
        var fileResult = Assert.IsType<FileStreamResult>(result);
        var exportData = await ExtractExportDataFromStream(fileResult.FileStream);

        Assert.True(exportData.ExportedAt >= beforeExport.AddSeconds(-1));
        Assert.True(exportData.ExportedAt <= afterExport.AddSeconds(1));
    }

    [Fact]
    public async Task ExportData_ExportJsonIsValidJson()
    {
        // Arrange
        var collections = new List<Collection>
        {
            new() { Id = 1, TenantId = TestTenantId, Name = "Test Collection", Slug = "test" }
        };
        _mockCollectionRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(collections);
        _mockCategoryRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Category>());
        _mockItemRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Item>());

        // Act
        var result = await _controller.ExportData();

        // Assert
        var fileResult = Assert.IsType<FileStreamResult>(result);
        var zipContents = await ReadStreamToByteArrayAsync(fileResult.FileStream);
        using var memoryStream = new MemoryStream(zipContents);
        using var archive = new ZipArchive(memoryStream, ZipArchiveMode.Read);
        var entry = archive.GetEntry("export.json");
        Assert.NotNull(entry);

        using var entryStream = entry.Open();
        using var reader = new StreamReader(entryStream);
        var json = await reader.ReadToEndAsync();

        // Should not throw - validates JSON is well-formed
        var document = JsonDocument.Parse(json);
        Assert.NotNull(document);
    }

    [Fact]
    public async Task ExportData_JsonUsesCamelCasePropertyNames()
    {
        // Arrange
        var collections = new List<Collection>
        {
            new() { Id = 1, TenantId = TestTenantId, Name = "Test", Slug = "test", HeroImageUrl = "http://example.com/img.jpg" }
        };
        _mockCollectionRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(collections);
        _mockCategoryRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Category>());
        _mockItemRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Item>());

        // Act
        var result = await _controller.ExportData();

        // Assert
        var fileResult = Assert.IsType<FileStreamResult>(result);
        var zipContents = await ReadStreamToByteArrayAsync(fileResult.FileStream);
        using var memoryStream = new MemoryStream(zipContents);
        using var archive = new ZipArchive(memoryStream, ZipArchiveMode.Read);
        var entry = archive.GetEntry("export.json");
        Assert.NotNull(entry);

        using var entryStream = entry.Open();
        using var reader = new StreamReader(entryStream);
        var json = await reader.ReadToEndAsync();

        Assert.Contains("\"exportedAt\"", json);
        Assert.Contains("\"collections\"", json);
        Assert.Contains("\"collectionId\"", json);
        Assert.Contains("\"heroImageUrl\"", json);
    }

    #endregion

    #region Helper Methods

    private static async Task<byte[]> ReadStreamToByteArrayAsync(Stream stream)
    {
        using var memoryStream = new MemoryStream();
        await stream.CopyToAsync(memoryStream);
        return memoryStream.ToArray();
    }

    private static async Task<ExportData> ExtractExportDataFromStream(Stream stream)
    {
        var zipContents = await ReadStreamToByteArrayAsync(stream);
        using var memoryStream = new MemoryStream(zipContents);
        using var archive = new ZipArchive(memoryStream, ZipArchiveMode.Read);
        var entry = archive.GetEntry("export.json");

        if (entry == null)
            throw new InvalidOperationException("export.json not found in ZIP archive");

        using var entryStream = entry.Open();
        using var reader = new StreamReader(entryStream);
        var json = await reader.ReadToEndAsync();

        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };

        return JsonSerializer.Deserialize<ExportData>(json, options)
            ?? throw new InvalidOperationException("Failed to deserialize export data");
    }

    #endregion
}
