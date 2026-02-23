using OneBigHead.Server.Controllers;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using System.Security.Claims;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class CollectionStatisticsTests
{
    private readonly Mock<ICollectionRepository> _mockCollectionRepository;
    private readonly Mock<ICategoryRepository> _mockCategoryRepository;
    private readonly Mock<IItemTemplateRepository> _mockItemTemplateRepository;
    private readonly Mock<IThemeRepository> _mockThemeRepository;
    private readonly Mock<ICollectionStatisticsRepository> _mockCollectionStatisticsRepository;
    private readonly Mock<ILogger<CollectionsController>> _mockLogger;
    private readonly CollectionsController _controller;
    private const int TestWorkspaceId = 1;
    private const int TestCollectionId = 10;

    public CollectionStatisticsTests()
    {
        _mockCollectionRepository = new Mock<ICollectionRepository>();
        _mockCategoryRepository = new Mock<ICategoryRepository>();
        _mockItemTemplateRepository = new Mock<IItemTemplateRepository>();
        _mockThemeRepository = new Mock<IThemeRepository>();
        _mockCollectionStatisticsRepository = new Mock<ICollectionStatisticsRepository>();
        _mockLogger = new Mock<ILogger<CollectionsController>>();
        _controller = new CollectionsController(
            _mockCollectionRepository.Object,
            _mockCategoryRepository.Object,
            _mockItemTemplateRepository.Object,
            _mockThemeRepository.Object,
            _mockCollectionStatisticsRepository.Object,
            _mockLogger.Object);

        var claims = new List<Claim>
        {
            new("workspace_id", TestWorkspaceId.ToString()),
            new("sub", "1"),
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

    [Fact]
    public async Task GetStatistics_ReturnsNotFound_WhenCollectionDoesNotExist()
    {
        // Arrange
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.GetStatistics(TestCollectionId);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    [Fact]
    public async Task GetStatistics_ReturnsOk_WithStatistics()
    {
        // Arrange
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test", Slug = "test" });

        _mockCollectionStatisticsRepository.Setup(r => r.GetAggregatesAsync(TestCollectionId))
            .ReturnsAsync(new Dictionary<CollectionStatisticType, long>
            {
                { CollectionStatisticType.ItemCount, 42 },
                { CollectionStatisticType.ImageCount, 10 },
                { CollectionStatisticType.TotalImageSizeBytes, 1048576 },
            });

        _mockCollectionStatisticsRepository.Setup(r => r.GetTopViewedItemsAsync(TestCollectionId, 10))
            .ReturnsAsync(new List<CollectionItemHighlight>
            {
                new() { ItemId = 1, ViewCount = 100, Item = new Item { Id = 1, Name = "Popular Item", WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId } },
                new() { ItemId = 2, ViewCount = 50, Item = new Item { Id = 2, Name = "Second Item", WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId } },
            });

        _mockCollectionStatisticsRepository.Setup(r => r.GetRecentlyAddedItemsAsync(TestCollectionId, TestWorkspaceId, 10))
            .ReturnsAsync(new List<Item>
            {
                new() { Id = 3, Name = "Newest", WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, CreatedAt = DateTime.UtcNow },
            });

        // Act
        var result = await _controller.GetStatistics(TestCollectionId);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<CollectionStatisticsResponse>(okResult.Value);
        Assert.Equal(42, response.ItemCount);
        Assert.Equal(10, response.ImageCount);
        Assert.Equal(1048576, response.TotalImageSizeBytes);
        Assert.Equal(2, response.TopViewedItems.Count);
        Assert.Equal("Popular Item", response.TopViewedItems[0].ItemName);
        Assert.Equal(100, response.TopViewedItems[0].ViewCount);
        Assert.Single(response.RecentlyAddedItems);
        Assert.Equal("Newest", response.RecentlyAddedItems[0].ItemName);
    }

    [Fact]
    public async Task GetStatistics_ReturnsZeroes_WhenNoStatisticsExist()
    {
        // Arrange
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test", Slug = "test" });

        _mockCollectionStatisticsRepository.Setup(r => r.GetAggregatesAsync(TestCollectionId))
            .ReturnsAsync(new Dictionary<CollectionStatisticType, long>());

        _mockCollectionStatisticsRepository.Setup(r => r.GetTopViewedItemsAsync(TestCollectionId, 10))
            .ReturnsAsync(new List<CollectionItemHighlight>());

        _mockCollectionStatisticsRepository.Setup(r => r.GetRecentlyAddedItemsAsync(TestCollectionId, TestWorkspaceId, 10))
            .ReturnsAsync(new List<Item>());

        // Act
        var result = await _controller.GetStatistics(TestCollectionId);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<CollectionStatisticsResponse>(okResult.Value);
        Assert.Equal(0, response.ItemCount);
        Assert.Equal(0, response.ImageCount);
        Assert.Equal(0, response.TotalImageSizeBytes);
        Assert.Empty(response.TopViewedItems);
        Assert.Empty(response.RecentlyAddedItems);
    }

    [Fact]
    public async Task GetStatistics_FiltersOutHighlightsWithNullItems()
    {
        // Arrange
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test", Slug = "test" });

        _mockCollectionStatisticsRepository.Setup(r => r.GetAggregatesAsync(TestCollectionId))
            .ReturnsAsync(new Dictionary<CollectionStatisticType, long>());

        _mockCollectionStatisticsRepository.Setup(r => r.GetTopViewedItemsAsync(TestCollectionId, 10))
            .ReturnsAsync(new List<CollectionItemHighlight>
            {
                new() { ItemId = 1, ViewCount = 100, Item = new Item { Id = 1, Name = "Valid", WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId } },
                new() { ItemId = 2, ViewCount = 50, Item = null },
            });

        _mockCollectionStatisticsRepository.Setup(r => r.GetRecentlyAddedItemsAsync(TestCollectionId, TestWorkspaceId, 10))
            .ReturnsAsync(new List<Item>());

        // Act
        var result = await _controller.GetStatistics(TestCollectionId);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<CollectionStatisticsResponse>(okResult.Value);
        Assert.Single(response.TopViewedItems);
        Assert.Equal("Valid", response.TopViewedItems[0].ItemName);
    }

    [Fact]
    public async Task GetStatistics_CallsRepositoryWithCorrectParameters()
    {
        // Arrange
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test", Slug = "test" });

        _mockCollectionStatisticsRepository.Setup(r => r.GetAggregatesAsync(TestCollectionId))
            .ReturnsAsync(new Dictionary<CollectionStatisticType, long>());
        _mockCollectionStatisticsRepository.Setup(r => r.GetTopViewedItemsAsync(TestCollectionId, 10))
            .ReturnsAsync(new List<CollectionItemHighlight>());
        _mockCollectionStatisticsRepository.Setup(r => r.GetRecentlyAddedItemsAsync(TestCollectionId, TestWorkspaceId, 10))
            .ReturnsAsync(new List<Item>());

        // Act
        await _controller.GetStatistics(TestCollectionId);

        // Assert
        _mockCollectionStatisticsRepository.Verify(r => r.GetAggregatesAsync(TestCollectionId), Times.Once);
        _mockCollectionStatisticsRepository.Verify(r => r.GetTopViewedItemsAsync(TestCollectionId, 10), Times.Once);
        _mockCollectionStatisticsRepository.Verify(r => r.GetRecentlyAddedItemsAsync(TestCollectionId, TestWorkspaceId, 10), Times.Once);
    }
}
