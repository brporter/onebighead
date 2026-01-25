using backend.Controllers;
using backend.Data;
using backend.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Security.Claims;

namespace backend.Tests.Controllers;

public class PropertySuggestionsControllerTests
{
    private readonly Mock<IPropertySuggestionRepository> _mockSuggestionRepository;
    private readonly Mock<ICollectionRepository> _mockCollectionRepository;
    private readonly PropertySuggestionsController _controller;
    private const int TestTenantId = 1;
    private const int TestUserId = 1;

    public PropertySuggestionsControllerTests()
    {
        _mockSuggestionRepository = new Mock<IPropertySuggestionRepository>();
        _mockCollectionRepository = new Mock<ICollectionRepository>();
        _controller = new PropertySuggestionsController(
            _mockSuggestionRepository.Object,
            _mockCollectionRepository.Object);

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

    #region GetSuggestions Tests

    [Fact]
    public async Task GetSuggestions_ReturnsOkResult_WithSuggestions()
    {
        // Arrange
        var collectionId = 1;
        var collection = new Collection { Id = collectionId, TenantId = TestTenantId, Name = "Test Collection", Slug = "test-collection" };
        var categories = new List<string> { "Category1", "Category2" };
        var names = new List<string> { "Name1", "Name2", "Name3" };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(collectionId, TestTenantId))
            .ReturnsAsync(collection);
        _mockSuggestionRepository.Setup(repo => repo.GetCategoriesAsync(collectionId, TestTenantId))
            .ReturnsAsync(categories);
        _mockSuggestionRepository.Setup(repo => repo.GetNamesAsync(collectionId, TestTenantId))
            .ReturnsAsync(names);

        // Act
        var result = await _controller.GetSuggestions(collectionId);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<PropertySuggestionsResponse>(okResult.Value);
        Assert.Equal(2, response.Categories.Count);
        Assert.Equal(3, response.Names.Count);
        Assert.Contains("Category1", response.Categories);
        Assert.Contains("Name1", response.Names);
    }

    [Fact]
    public async Task GetSuggestions_ReturnsOkResult_WithEmptyLists_WhenNoSuggestions()
    {
        // Arrange
        var collectionId = 1;
        var collection = new Collection { Id = collectionId, TenantId = TestTenantId, Name = "Test Collection", Slug = "test-collection" };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(collectionId, TestTenantId))
            .ReturnsAsync(collection);
        _mockSuggestionRepository.Setup(repo => repo.GetCategoriesAsync(collectionId, TestTenantId))
            .ReturnsAsync(new List<string>());
        _mockSuggestionRepository.Setup(repo => repo.GetNamesAsync(collectionId, TestTenantId))
            .ReturnsAsync(new List<string>());

        // Act
        var result = await _controller.GetSuggestions(collectionId);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<PropertySuggestionsResponse>(okResult.Value);
        Assert.Empty(response.Categories);
        Assert.Empty(response.Names);
    }

    [Fact]
    public async Task GetSuggestions_ReturnsNotFound_WhenCollectionDoesNotExist()
    {
        // Arrange
        var collectionId = 999;
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(collectionId, TestTenantId))
            .ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.GetSuggestions(collectionId);

        // Assert
        var notFoundResult = Assert.IsType<NotFoundObjectResult>(result.Result);
        Assert.Equal("Collection not found", notFoundResult.Value);
    }

    [Fact]
    public async Task GetSuggestions_ReturnsNotFound_WhenCollectionBelongsToDifferentTenant()
    {
        // Arrange
        var collectionId = 1;
        // Collection exists but belongs to a different tenant, so GetByIdAsync returns null for our tenant
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(collectionId, TestTenantId))
            .ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.GetSuggestions(collectionId);

        // Assert
        var notFoundResult = Assert.IsType<NotFoundObjectResult>(result.Result);
        Assert.Equal("Collection not found", notFoundResult.Value);
    }

    [Fact]
    public async Task GetSuggestions_CallsRepositoryWithCorrectParameters()
    {
        // Arrange
        var collectionId = 5;
        var collection = new Collection { Id = collectionId, TenantId = TestTenantId, Name = "Test Collection", Slug = "test-collection" };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(collectionId, TestTenantId))
            .ReturnsAsync(collection);
        _mockSuggestionRepository.Setup(repo => repo.GetCategoriesAsync(collectionId, TestTenantId))
            .ReturnsAsync(new List<string>());
        _mockSuggestionRepository.Setup(repo => repo.GetNamesAsync(collectionId, TestTenantId))
            .ReturnsAsync(new List<string>());

        // Act
        await _controller.GetSuggestions(collectionId);

        // Assert
        _mockCollectionRepository.Verify(repo => repo.GetByIdAsync(collectionId, TestTenantId), Times.Once);
        _mockSuggestionRepository.Verify(repo => repo.GetCategoriesAsync(collectionId, TestTenantId), Times.Once);
        _mockSuggestionRepository.Verify(repo => repo.GetNamesAsync(collectionId, TestTenantId), Times.Once);
    }

    #endregion

    #region SyncSuggestions Tests

    [Fact]
    public async Task SyncSuggestions_ReturnsOkResult_WithUpdatedSuggestions()
    {
        // Arrange
        var collectionId = 1;
        var collection = new Collection { Id = collectionId, TenantId = TestTenantId, Name = "Test Collection", Slug = "test-collection" };
        var categories = new List<string> { "SyncedCategory1", "SyncedCategory2" };
        var names = new List<string> { "SyncedName1" };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(collectionId, TestTenantId))
            .ReturnsAsync(collection);
        _mockSuggestionRepository.Setup(repo => repo.SyncSuggestionsAsync(collectionId, TestTenantId, It.IsAny<IEnumerable<string>>(), It.IsAny<IEnumerable<string>>()))
            .Returns(Task.CompletedTask);
        _mockSuggestionRepository.Setup(repo => repo.GetCategoriesAsync(collectionId, TestTenantId))
            .ReturnsAsync(categories);
        _mockSuggestionRepository.Setup(repo => repo.GetNamesAsync(collectionId, TestTenantId))
            .ReturnsAsync(names);

        // Act
        var result = await _controller.SyncSuggestions(collectionId);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<PropertySuggestionsResponse>(okResult.Value);
        Assert.Equal(2, response.Categories.Count);
        Assert.Single(response.Names);
        Assert.Contains("SyncedCategory1", response.Categories);
        Assert.Contains("SyncedName1", response.Names);
    }

    [Fact]
    public async Task SyncSuggestions_ReturnsNotFound_WhenCollectionDoesNotExist()
    {
        // Arrange
        var collectionId = 999;
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(collectionId, TestTenantId))
            .ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.SyncSuggestions(collectionId);

        // Assert
        var notFoundResult = Assert.IsType<NotFoundObjectResult>(result.Result);
        Assert.Equal("Collection not found", notFoundResult.Value);
    }

    [Fact]
    public async Task SyncSuggestions_ReturnsNotFound_WhenCollectionBelongsToDifferentTenant()
    {
        // Arrange
        var collectionId = 1;
        // Collection exists but belongs to a different tenant, so GetByIdAsync returns null for our tenant
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(collectionId, TestTenantId))
            .ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.SyncSuggestions(collectionId);

        // Assert
        var notFoundResult = Assert.IsType<NotFoundObjectResult>(result.Result);
        Assert.Equal("Collection not found", notFoundResult.Value);
    }

    [Fact]
    public async Task SyncSuggestions_CallsSyncBeforeGettingSuggestions()
    {
        // Arrange
        var collectionId = 1;
        var collection = new Collection { Id = collectionId, TenantId = TestTenantId, Name = "Test Collection", Slug = "test-collection" };
        var callOrder = new List<string>();

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(collectionId, TestTenantId))
            .ReturnsAsync(collection);
        _mockSuggestionRepository.Setup(repo => repo.SyncSuggestionsAsync(collectionId, TestTenantId, It.IsAny<IEnumerable<string>>(), It.IsAny<IEnumerable<string>>()))
            .Callback(() => callOrder.Add("Sync"))
            .Returns(Task.CompletedTask);
        _mockSuggestionRepository.Setup(repo => repo.GetCategoriesAsync(collectionId, TestTenantId))
            .Callback(() => callOrder.Add("GetCategories"))
            .ReturnsAsync(new List<string>());
        _mockSuggestionRepository.Setup(repo => repo.GetNamesAsync(collectionId, TestTenantId))
            .Callback(() => callOrder.Add("GetNames"))
            .ReturnsAsync(new List<string>());

        // Act
        await _controller.SyncSuggestions(collectionId);

        // Assert
        Assert.Equal(3, callOrder.Count);
        Assert.Equal("Sync", callOrder[0]);
    }

    [Fact]
    public async Task SyncSuggestions_CallsRepositoryWithCorrectParameters()
    {
        // Arrange
        var collectionId = 7;
        var collection = new Collection { Id = collectionId, TenantId = TestTenantId, Name = "Test Collection", Slug = "test-collection" };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(collectionId, TestTenantId))
            .ReturnsAsync(collection);
        _mockSuggestionRepository.Setup(repo => repo.SyncSuggestionsAsync(collectionId, TestTenantId, It.IsAny<IEnumerable<string>>(), It.IsAny<IEnumerable<string>>()))
            .Returns(Task.CompletedTask);
        _mockSuggestionRepository.Setup(repo => repo.GetCategoriesAsync(collectionId, TestTenantId))
            .ReturnsAsync(new List<string>());
        _mockSuggestionRepository.Setup(repo => repo.GetNamesAsync(collectionId, TestTenantId))
            .ReturnsAsync(new List<string>());

        // Act
        await _controller.SyncSuggestions(collectionId);

        // Assert
        _mockCollectionRepository.Verify(repo => repo.GetByIdAsync(collectionId, TestTenantId), Times.Once);
        _mockSuggestionRepository.Verify(repo => repo.SyncSuggestionsAsync(collectionId, TestTenantId, It.IsAny<IEnumerable<string>>(), It.IsAny<IEnumerable<string>>()), Times.Once);
        _mockSuggestionRepository.Verify(repo => repo.GetCategoriesAsync(collectionId, TestTenantId), Times.Once);
        _mockSuggestionRepository.Verify(repo => repo.GetNamesAsync(collectionId, TestTenantId), Times.Once);
    }

    [Fact]
    public async Task SyncSuggestions_DoesNotCallSuggestionRepository_WhenCollectionNotFound()
    {
        // Arrange
        var collectionId = 999;
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(collectionId, TestTenantId))
            .ReturnsAsync((Collection?)null);

        // Act
        await _controller.SyncSuggestions(collectionId);

        // Assert
        _mockSuggestionRepository.Verify(repo => repo.SyncSuggestionsAsync(It.IsAny<int>(), It.IsAny<int>(), It.IsAny<IEnumerable<string>>(), It.IsAny<IEnumerable<string>>()), Times.Never);
        _mockSuggestionRepository.Verify(repo => repo.GetCategoriesAsync(It.IsAny<int>(), It.IsAny<int>()), Times.Never);
        _mockSuggestionRepository.Verify(repo => repo.GetNamesAsync(It.IsAny<int>(), It.IsAny<int>()), Times.Never);
    }

    #endregion
}
