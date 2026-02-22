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
    private readonly Mock<ICategoryRepository> _mockCategoryRepository;
    private readonly Mock<IItemTemplateRepository> _mockItemTemplateRepository;
    private readonly Mock<IThemeRepository> _mockThemeRepository;
    private readonly Mock<ICollectionStatisticsRepository> _mockCollectionStatisticsRepository;
    private readonly Mock<ILogger<CollectionsController>> _mockLogger;
    private readonly CollectionsController _controller;
    private const int TestWorkspaceId = 1;
    private const int TestUserId = 1;

    public CollectionsControllerTests()
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
            WorkspaceId = TestWorkspaceId,
            Name = "New Collection",
            Description = "Description",
            Slug = "new-collection"
        };

        _mockCollectionRepository.Setup(repo => repo.GetBySlugAsync("new-collection", TestWorkspaceId))
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
        var existingCollection = new Collection { Id = 1, WorkspaceId = TestWorkspaceId, Name = "Test", Slug = "test-collection" };
        var createdCollection = new Collection
        {
            Id = 2,
            WorkspaceId = TestWorkspaceId,
            Name = "Test Collection",
            Slug = "test-collection-123"
        };

        _mockCollectionRepository.Setup(repo => repo.GetBySlugAsync("test-collection", TestWorkspaceId))
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
        var createdCollection = new Collection { Id = 1, WorkspaceId = TestWorkspaceId, Name = "New Collection", Slug = "new-collection" };

        _mockCollectionRepository.Setup(repo => repo.GetBySlugAsync(It.IsAny<string>(), TestWorkspaceId))
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
    public async Task SetupCollection_CreatesCollectionWithUnassignedCategory()
    {
        // Arrange
        var theme = new CollectionTheme
        {
            Id = 1,
            Name = "General",
            ThemeTemplates = new List<CollectionThemeTemplate>(),
            ThemeCategories = new List<CollectionThemeCategory>()
        };

        var createdCollection = new Collection
        {
            Id = 1,
            WorkspaceId = TestWorkspaceId,
            Name = "Test Collection",
            Slug = "test-collection"
        };

        var request = new SetupCollectionRequest { Name = "Test Collection", ThemeId = 1 };

        _mockThemeRepository.Setup(repo => repo.GetByIdAsync(1))
            .ReturnsAsync(theme);
        _mockCollectionRepository.Setup(repo => repo.CreateAsync(It.IsAny<Collection>()))
            .ReturnsAsync(createdCollection);
        _mockCategoryRepository.Setup(repo => repo.CreateAsync(It.IsAny<Category>()))
            .ReturnsAsync((Category c) => c);

        // Act
        var result = await _controller.SetupCollection(request);

        // Assert
        var createdResult = Assert.IsType<CreatedAtActionResult>(result.Result);
        
        // Verify Unassigned category was created
        _mockCategoryRepository.Verify(
            repo => repo.CreateAsync(It.Is<Category>(c => 
                c.Name == "Unassigned Items" && 
                c.IsSystem == true && 
                c.CollectionId == 1)),
            Times.Once);
    }

    [Fact]
    public async Task SetupCollection_AssociatesThemeTemplates()
    {
        // Arrange
        var theme = new CollectionTheme
        {
            Id = 1,
            Name = "Books",
            ThemeTemplates = new List<CollectionThemeTemplate>
            {
                new() { ThemeId = 1, ItemTemplateId = 10, SortOrder = 1 },
                new() { ThemeId = 1, ItemTemplateId = 11, SortOrder = 2 }
            },
            ThemeCategories = new List<CollectionThemeCategory>()
        };

        var createdCollection = new Collection
        {
            Id = 5,
            WorkspaceId = TestWorkspaceId,
            Name = "My Books",
            Slug = "my-books"
        };

        var request = new SetupCollectionRequest { Name = "My Books", ThemeId = 1 };

        _mockThemeRepository.Setup(repo => repo.GetByIdAsync(1))
            .ReturnsAsync(theme);
        _mockCollectionRepository.Setup(repo => repo.CreateAsync(It.IsAny<Collection>()))
            .ReturnsAsync(createdCollection);
        _mockCategoryRepository.Setup(repo => repo.CreateAsync(It.IsAny<Category>()))
            .ReturnsAsync((Category c) => c);

        // Act
        var result = await _controller.SetupCollection(request);

        // Assert - now uses batch association
        _mockItemTemplateRepository.Verify(
            repo => repo.AssociateMultipleWithCollectionAsync(
                It.Is<IEnumerable<int>>(ids => ids.Count() == 2 && ids.Contains(10) && ids.Contains(11)),
                5),
            Times.Once);
    }

    [Fact]
    public async Task SetupCollection_CreatesCategoriesWithParentLinkage()
    {
        // Arrange
        var theme = new CollectionTheme
        {
            Id = 1,
            Name = "Books",
            ThemeTemplates = new List<CollectionThemeTemplate>(),
            ThemeCategories = new List<CollectionThemeCategory>
            {
                new() { ThemeId = 1, Name = "Fiction", Description = "Fiction books", ParentName = null, SortOrder = 1 },
                new() { ThemeId = 1, Name = "Sci-Fi", Description = "Science fiction", ParentName = "Fiction", SortOrder = 1 }
            }
        };

        var createdCollection = new Collection
        {
            Id = 5,
            WorkspaceId = TestWorkspaceId,
            Name = "My Books",
            Slug = "my-books"
        };

        var request = new SetupCollectionRequest { Name = "My Books", ThemeId = 1 };
        var categoryIdCounter = 100;
        var createdCategories = new List<Category>();

        _mockThemeRepository.Setup(repo => repo.GetByIdAsync(1))
            .ReturnsAsync(theme);
        _mockCollectionRepository.Setup(repo => repo.CreateAsync(It.IsAny<Collection>()))
            .ReturnsAsync(createdCollection);
        // Unassigned category gets ID 100
        _mockCategoryRepository.Setup(repo => repo.CreateAsync(It.IsAny<Category>()))
            .ReturnsAsync((Category c) =>
            {
                c.Id = categoryIdCounter++;
                return c;
            });
        // Iterative batch creation - track what gets created
        _mockCategoryRepository.Setup(repo => repo.CreateManyAsync(It.IsAny<IEnumerable<Category>>()))
            .ReturnsAsync((IEnumerable<Category> cats) =>
            {
                var result = new List<Category>();
                foreach (var c in cats)
                {
                    c.Id = categoryIdCounter++;
                    result.Add(c);
                    createdCategories.Add(c);
                }
                return result;
            });

        // Act
        var result = await _controller.SetupCollection(request);

        // Assert - verify categories were created with proper parent linkage
        // Fiction should be created as root (no parent)
        var fiction = createdCategories.FirstOrDefault(c => c.Name == "Fiction");
        Assert.NotNull(fiction);
        Assert.Null(fiction.ParentCategoryId);
        
        // Sci-Fi should be created with Fiction as parent
        var sciFi = createdCategories.FirstOrDefault(c => c.Name == "Sci-Fi");
        Assert.NotNull(sciFi);
        Assert.Equal(fiction.Id, sciFi.ParentCategoryId);
    }

    #endregion
}
