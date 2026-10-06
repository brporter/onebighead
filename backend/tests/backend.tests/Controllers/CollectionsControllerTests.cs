using OneBigHead.Server.Services;
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
public class CollectionsControllerTests
{
    private readonly Mock<ICollectionRepository> _mockCollectionRepository;
    private readonly Mock<IItemTemplateRepository> _mockItemTemplateRepository = new();
    private readonly Mock<ICollectionSetupService> _mockSetupService = new();
    private readonly Mock<IThemeRepository> _mockThemeRepository;
    private readonly Mock<ICollectionStatisticsRepository> _mockCollectionStatisticsRepository;
    private readonly CollectionsController _controller;
    private const int TestWorkspaceId = 1;
    private const int TestUserId = 1;

    public CollectionsControllerTests()
    {
        _mockCollectionRepository = new Mock<ICollectionRepository>();
        _mockThemeRepository = new Mock<IThemeRepository>();
        _mockCollectionStatisticsRepository = new Mock<ICollectionStatisticsRepository>();
        _controller = new CollectionsController(
            _mockCollectionRepository.Object,
            _mockItemTemplateRepository.Object,
            _mockSetupService.Object,
            _mockThemeRepository.Object,
            _mockCollectionStatisticsRepository.Object);

        var claims = new List<Claim>
        {
            new("workspace_id", TestWorkspaceId.ToString()),
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

    #region GetCollections Tests

    [Fact]
    public async Task GetCollections_ReturnsOkResult_WithListOfCollections()
    {
        // Arrange
        var collections = new List<Collection>
        {
            new() { Id = 1, WorkspaceId = TestWorkspaceId, Name = "Collection 1", Slug = "collection-1" },
            new() { Id = 2, WorkspaceId = TestWorkspaceId, Name = "Collection 2", Slug = "collection-2" }
        };
        _mockCollectionRepository.Setup(repo => repo.GetAllAsync(TestWorkspaceId))
            .ReturnsAsync(collections);

        // Act
        var result = await _controller.GetCollections();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCollections = Assert.IsAssignableFrom<IEnumerable<Collection>>(okResult.Value);
        Assert.Equal(2, returnedCollections.Count());
    }

    [Fact]
    public async Task GetCollections_ReturnsOkResult_WithEmptyList_WhenNoCollections()
    {
        // Arrange
        _mockCollectionRepository.Setup(repo => repo.GetAllAsync(TestWorkspaceId))
            .ReturnsAsync(new List<Collection>());

        // Act
        var result = await _controller.GetCollections();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCollections = Assert.IsAssignableFrom<IEnumerable<Collection>>(okResult.Value);
        Assert.Empty(returnedCollections);
    }

    #endregion

    #region GetCollection Tests

    [Fact]
    public async Task GetCollection_ReturnsOkResult_WhenCollectionExists()
    {
        // Arrange
        var collection = new Collection { Id = 1, WorkspaceId = TestWorkspaceId, Name = "Test Collection", Slug = "test-collection" };
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(collection);

        // Act
        var result = await _controller.GetCollection(1);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCollection = Assert.IsType<Collection>(okResult.Value);
        Assert.Equal("Test Collection", returnedCollection.Name);
    }

    [Fact]
    public async Task GetCollection_ReturnsNotFound_WhenCollectionDoesNotExist()
    {
        // Arrange
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(999, TestWorkspaceId))
            .ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.GetCollection(999);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    #endregion

    #region GetCollectionBySlug Tests

    [Fact]
    public async Task GetCollectionBySlug_ReturnsOkResult_WhenCollectionExists()
    {
        // Arrange
        var collection = new Collection { Id = 1, WorkspaceId = TestWorkspaceId, Name = "Test Collection", Slug = "test-collection" };
        _mockCollectionRepository.Setup(repo => repo.GetBySlugAsync("test-collection", TestWorkspaceId))
            .ReturnsAsync(collection);

        // Act
        var result = await _controller.GetCollectionBySlug("test-collection");

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCollection = Assert.IsType<Collection>(okResult.Value);
        Assert.Equal("test-collection", returnedCollection.Slug);
    }

    [Fact]
    public async Task GetCollectionBySlug_ReturnsNotFound_WhenCollectionDoesNotExist()
    {
        // Arrange
        _mockCollectionRepository.Setup(repo => repo.GetBySlugAsync("nonexistent", TestWorkspaceId))
            .ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.GetCollectionBySlug("nonexistent");

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    #endregion

    [Fact]
    public async Task CreateCollection_DelegatesSetupAndReturnsCreatedResource()
    {
        var created = new Collection { Id = 42, WorkspaceId = TestWorkspaceId, Name = "New" };
        _mockSetupService.Setup(s => s.CreateAsync(It.IsAny<Collection>(), null)).ReturnsAsync(created);
        var result = await _controller.CreateCollection(new CreateCollectionRequest { Name = "New", Description = "Details", HeroImageUrl = "/hero.jpg" });
        var response = Assert.IsType<CreatedAtActionResult>(result.Result);
        Assert.Same(created, response.Value);
        Assert.Equal(42, response.RouteValues!["id"]);
        _mockSetupService.Verify(s => s.CreateAsync(It.Is<Collection>(c => c.WorkspaceId == TestWorkspaceId && c.Name == "New" && c.Description == "Details" && c.HeroImageUrl == "/hero.jpg"), null), Times.Once);
    }


    #region UpdateCollection Tests

    [Fact]
    public async Task UpdateCollection_ReturnsOkResult_WhenCollectionExists()
    {
        // Arrange
        var request = new UpdateCollectionRequest
        {
            Name = "Updated Collection",
            Description = "Updated Description"
        };
        var existingCollection = new Collection { Id = 1, WorkspaceId = TestWorkspaceId, Name = "Old Name", Slug = "old-name" };
        var updatedCollection = new Collection
        {
            Id = 1,
            WorkspaceId = TestWorkspaceId,
            Name = "Updated Collection",
            Description = "Updated Description",
            Slug = "updated-collection"
        };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(existingCollection);
        _mockCollectionRepository.Setup(repo => repo.GetBySlugAsync("updated-collection", TestWorkspaceId))
            .ReturnsAsync((Collection?)null);
        _mockCollectionRepository.Setup(repo => repo.UpdateAsync(1, It.IsAny<Collection>(), TestWorkspaceId))
            .ReturnsAsync(updatedCollection);

        // Act
        var result = await _controller.UpdateCollection(1, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCollection = Assert.IsType<Collection>(okResult.Value);
        Assert.Equal("Updated Collection", returnedCollection.Name);
    }

    [Fact]
    public async Task UpdateCollection_PreservesExistingVisibility()
    {
        // Arrange
        var request = new UpdateCollectionRequest
        {
            Name = "Updated Collection",
            Description = "Updated Description"
        };
        var existingCollection = new Collection { Id = 1, WorkspaceId = TestWorkspaceId, Name = "Old Name", Slug = "old-name", Visibility = Visibility.Public };

        Collection? capturedCollection = null;
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(existingCollection);
        _mockCollectionRepository.Setup(repo => repo.GetBySlugAsync("updated-collection", TestWorkspaceId))
            .ReturnsAsync((Collection?)null);
        _mockCollectionRepository.Setup(repo => repo.UpdateAsync(1, It.IsAny<Collection>(), TestWorkspaceId))
            .Callback<int, Collection, int>((id, c, ws) => capturedCollection = c)
            .ReturnsAsync((int id, Collection c, int ws) => new Collection { Id = id, WorkspaceId = ws, Name = c.Name, Visibility = c.Visibility });

        // Act
        await _controller.UpdateCollection(1, request);

        // Assert - Visibility should be preserved from existing collection (Public)
        Assert.NotNull(capturedCollection);
        Assert.Equal(Visibility.Public, capturedCollection!.Visibility);
    }

    [Fact]
    public async Task UpdateCollection_ReturnsNotFound_WhenCollectionDoesNotExist()
    {
        // Arrange
        var request = new UpdateCollectionRequest { Name = "Updated Collection" };
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(999, TestWorkspaceId))
            .ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.UpdateCollection(999, request);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    #endregion

    #region DeleteCollection Tests

    [Fact]
    public async Task DeleteCollection_ReturnsNoContent_WhenCollectionExists()
    {
        // Arrange
        _mockCollectionRepository.Setup(repo => repo.GetCountAsync(TestWorkspaceId))
            .ReturnsAsync(2);
        _mockCollectionRepository.Setup(repo => repo.DeleteAsync(1, TestWorkspaceId))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.DeleteCollection(1);

        // Assert
        Assert.IsType<NoContentResult>(result);
    }

    [Fact]
    public async Task DeleteCollection_ReturnsNotFound_WhenCollectionDoesNotExist()
    {
        // Arrange
        _mockCollectionRepository.Setup(repo => repo.GetCountAsync(TestWorkspaceId))
            .ReturnsAsync(2);
        _mockCollectionRepository.Setup(repo => repo.DeleteAsync(999, TestWorkspaceId))
            .ReturnsAsync(false);

        // Act
        var result = await _controller.DeleteCollection(999);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task DeleteCollection_ReturnsBadRequest_WhenDeletingLastCollection()
    {
        // Arrange
        _mockCollectionRepository.Setup(repo => repo.GetCountAsync(TestWorkspaceId))
            .ReturnsAsync(1);

        // Act
        var result = await _controller.DeleteCollection(1);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("Cannot delete the last collection", badRequestResult.Value?.ToString());
    }

    #endregion

    #region SetupCollection Tests

    [Fact]
    public async Task SetupCollection_ReturnsBadRequest_WhenThemeNotFound()
    {
        // Arrange
        var request = new SetupCollectionRequest { Name = "Test Collection", ThemeId = 999 };
        _mockThemeRepository.Setup(repo => repo.GetByIdAsync(999))
            .ReturnsAsync((CollectionTheme?)null);

        // Act
        var result = await _controller.SetupCollection(request);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
        Assert.Contains("Invalid theme", badRequestResult.Value?.ToString());
    }

    [Fact]
    public async Task SetupCollection_DelegatesThemeAndDefaultsDescription()
    {
        var theme = new CollectionTheme { Id = 1, Name = "Theme" };
        _mockThemeRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(theme);
        var created = new Collection { Id = 42, Name = "New" };
        _mockSetupService.Setup(s => s.CreateAsync(It.IsAny<Collection>(), theme)).ReturnsAsync(created);
        var result = await _controller.SetupCollection(new SetupCollectionRequest { Name = "New", ThemeId = 1 });
        Assert.Same(created, Assert.IsType<CreatedAtActionResult>(result.Result).Value);
        _mockSetupService.Verify(s => s.CreateAsync(It.Is<Collection>(c => c.WorkspaceId == TestWorkspaceId && c.Name == "New" && c.Description == ""), theme), Times.Once);
    }

    #endregion
}
