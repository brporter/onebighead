using backend.Controllers;
using backend.Data;
using backend.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Security.Claims;

namespace backend.Tests.Controllers;

public class CollectionsControllerTests
{
    private readonly Mock<ICollectionRepository> _mockCollectionRepository;
    private readonly Mock<ICategoryRepository> _mockCategoryRepository;
    private readonly CollectionsController _controller;
    private const int TestTenantId = 1;

    public CollectionsControllerTests()
    {
        _mockCollectionRepository = new Mock<ICollectionRepository>();
        _mockCategoryRepository = new Mock<ICategoryRepository>();
        _controller = new CollectionsController(_mockCollectionRepository.Object, _mockCategoryRepository.Object);

        var claims = new List<Claim>
        {
            new("tenant_id", TestTenantId.ToString()),
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
            new() { Id = 1, TenantId = TestTenantId, Name = "Collection 1", Slug = "collection-1" },
            new() { Id = 2, TenantId = TestTenantId, Name = "Collection 2", Slug = "collection-2" }
        };
        _mockCollectionRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
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
        _mockCollectionRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
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
        var collection = new Collection { Id = 1, TenantId = TestTenantId, Name = "Test Collection", Slug = "test-collection" };
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(1, TestTenantId))
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
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(999, TestTenantId))
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
        var collection = new Collection { Id = 1, TenantId = TestTenantId, Name = "Test Collection", Slug = "test-collection" };
        _mockCollectionRepository.Setup(repo => repo.GetBySlugAsync("test-collection", TestTenantId))
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
        _mockCollectionRepository.Setup(repo => repo.GetBySlugAsync("nonexistent", TestTenantId))
            .ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.GetCollectionBySlug("nonexistent");

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    #endregion

    #region CreateCollection Tests

    [Fact]
    public async Task CreateCollection_ReturnsCreatedAtAction_WithNewCollection()
    {
        // Arrange
        var request = new CreateCollectionRequest
        {
            Name = "New Collection",
            Description = "Description"
        };
        var createdCollection = new Collection
        {
            Id = 1,
            TenantId = TestTenantId,
            Name = "New Collection",
            Description = "Description",
            Slug = "new-collection"
        };

        _mockCollectionRepository.Setup(repo => repo.GetBySlugAsync("new-collection", TestTenantId))
            .ReturnsAsync((Collection?)null);
        _mockCollectionRepository.Setup(repo => repo.CreateAsync(It.IsAny<Collection>()))
            .ReturnsAsync(createdCollection);
        _mockCategoryRepository.Setup(repo => repo.CreateAsync(It.IsAny<Category>()))
            .ReturnsAsync(new Category { Id = 1, Name = "Unassigned Items" });

        // Act
        var result = await _controller.CreateCollection(request);

        // Assert
        var createdResult = Assert.IsType<CreatedAtActionResult>(result.Result);
        Assert.Equal(nameof(_controller.GetCollection), createdResult.ActionName);
        var returnedCollection = Assert.IsType<Collection>(createdResult.Value);
        Assert.Equal("New Collection", returnedCollection.Name);
    }

    [Fact]
    public async Task CreateCollection_GeneratesUniqueSlug_WhenSlugExists()
    {
        // Arrange
        var request = new CreateCollectionRequest
        {
            Name = "Test Collection"
        };
        var existingCollection = new Collection { Id = 1, TenantId = TestTenantId, Name = "Test", Slug = "test-collection" };
        var createdCollection = new Collection
        {
            Id = 2,
            TenantId = TestTenantId,
            Name = "Test Collection",
            Slug = "test-collection-123"
        };

        _mockCollectionRepository.Setup(repo => repo.GetBySlugAsync("test-collection", TestTenantId))
            .ReturnsAsync(existingCollection);
        _mockCollectionRepository.Setup(repo => repo.CreateAsync(It.IsAny<Collection>()))
            .ReturnsAsync(createdCollection);
        _mockCategoryRepository.Setup(repo => repo.CreateAsync(It.IsAny<Category>()))
            .ReturnsAsync(new Category { Id = 1, Name = "Unassigned Items" });

        // Act
        var result = await _controller.CreateCollection(request);

        // Assert
        var createdResult = Assert.IsType<CreatedAtActionResult>(result.Result);
        _mockCollectionRepository.Verify(repo => repo.CreateAsync(
            It.Is<Collection>(c => c.Slug.StartsWith("test-collection-"))), Times.Once);
    }

    [Fact]
    public async Task CreateCollection_CreatesUnassignedCategory()
    {
        // Arrange
        var request = new CreateCollectionRequest { Name = "New Collection" };
        var createdCollection = new Collection { Id = 1, TenantId = TestTenantId, Name = "New Collection", Slug = "new-collection" };

        _mockCollectionRepository.Setup(repo => repo.GetBySlugAsync(It.IsAny<string>(), TestTenantId))
            .ReturnsAsync((Collection?)null);
        _mockCollectionRepository.Setup(repo => repo.CreateAsync(It.IsAny<Collection>()))
            .ReturnsAsync(createdCollection);
        _mockCategoryRepository.Setup(repo => repo.CreateAsync(It.IsAny<Category>()))
            .ReturnsAsync(new Category { Id = 1, Name = "Unassigned Items" });

        // Act
        await _controller.CreateCollection(request);

        // Assert
        _mockCategoryRepository.Verify(repo => repo.CreateAsync(
            It.Is<Category>(c => c.Name == "Unassigned Items" && c.IsSystem && c.CollectionId == 1)), Times.Once);
    }

    #endregion

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
        var existingCollection = new Collection { Id = 1, TenantId = TestTenantId, Name = "Old Name", Slug = "old-name" };
        var updatedCollection = new Collection
        {
            Id = 1,
            TenantId = TestTenantId,
            Name = "Updated Collection",
            Description = "Updated Description",
            Slug = "updated-collection"
        };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(1, TestTenantId))
            .ReturnsAsync(existingCollection);
        _mockCollectionRepository.Setup(repo => repo.GetBySlugAsync("updated-collection", TestTenantId))
            .ReturnsAsync((Collection?)null);
        _mockCollectionRepository.Setup(repo => repo.UpdateAsync(1, It.IsAny<Collection>(), TestTenantId))
            .ReturnsAsync(updatedCollection);

        // Act
        var result = await _controller.UpdateCollection(1, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCollection = Assert.IsType<Collection>(okResult.Value);
        Assert.Equal("Updated Collection", returnedCollection.Name);
    }

    [Fact]
    public async Task UpdateCollection_ReturnsNotFound_WhenCollectionDoesNotExist()
    {
        // Arrange
        var request = new UpdateCollectionRequest { Name = "Updated Collection" };
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(999, TestTenantId))
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
        _mockCollectionRepository.Setup(repo => repo.GetCountAsync(TestTenantId))
            .ReturnsAsync(2);
        _mockCollectionRepository.Setup(repo => repo.DeleteAsync(1, TestTenantId))
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
        _mockCollectionRepository.Setup(repo => repo.GetCountAsync(TestTenantId))
            .ReturnsAsync(2);
        _mockCollectionRepository.Setup(repo => repo.DeleteAsync(999, TestTenantId))
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
        _mockCollectionRepository.Setup(repo => repo.GetCountAsync(TestTenantId))
            .ReturnsAsync(1);

        // Act
        var result = await _controller.DeleteCollection(1);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("Cannot delete the last collection", badRequestResult.Value?.ToString());
    }

    #endregion
}
