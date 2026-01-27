using backend.Controllers;
using backend.Data;
using backend.DTOs;
using backend.Models;
using backend.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Security.Claims;

namespace backend.Tests.Controllers;

[Trait("Category", "Unit")]
public class ItemsControllerTests
{
    private readonly Mock<IItemRepository> _mockItemRepository;
    private readonly Mock<ICategoryRepository> _mockCategoryRepository;
    private readonly Mock<ICollectionRepository> _mockCollectionRepository;
    private readonly Mock<IVisibilityService> _mockVisibilityService;
    private readonly ItemsController _controller;
    private const int TestTenantId = 1;
    private const int TestCollectionId = 1;
    private const int TestCategoryId = 1;

    public ItemsControllerTests()
    {
        _mockItemRepository = new Mock<IItemRepository>();
        _mockCategoryRepository = new Mock<ICategoryRepository>();
        _mockCollectionRepository = new Mock<ICollectionRepository>();
        _mockVisibilityService = new Mock<IVisibilityService>();
        _controller = new ItemsController(
            _mockItemRepository.Object, 
            _mockCategoryRepository.Object,
            _mockCollectionRepository.Object,
            _mockVisibilityService.Object);

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

    #region GetItems Tests

    [Fact]
    public async Task GetItems_ReturnsOkResult_WithListOfItems()
    {
        // Arrange
        var items = new List<Item>
        {
            new() { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Item 1", CategoryId = TestCategoryId },
            new() { Id = 2, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Item 2", CategoryId = TestCategoryId }
        };
        _mockItemRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(items);

        // Act
        var result = await _controller.GetItems();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedItems = Assert.IsAssignableFrom<IEnumerable<Item>>(okResult.Value);
        Assert.Equal(2, returnedItems.Count());
    }

    [Fact]
    public async Task GetItems_ReturnsOkResult_WithEmptyList_WhenNoItems()
    {
        // Arrange
        _mockItemRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Item>());

        // Act
        var result = await _controller.GetItems();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedItems = Assert.IsAssignableFrom<IEnumerable<Item>>(okResult.Value);
        Assert.Empty(returnedItems);
    }

    [Fact]
    public async Task GetItems_FiltersByCategory_WhenCategoryIdProvided()
    {
        // Arrange
        var items = new List<Item>
        {
            new() { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Item 1", CategoryId = TestCategoryId }
        };
        _mockItemRepository.Setup(repo => repo.GetByCategoryIdsAsync(It.IsAny<IEnumerable<int>>(), TestTenantId))
            .ReturnsAsync(items);

        // Act
        var result = await _controller.GetItems(categoryId: TestCategoryId);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedItems = Assert.IsAssignableFrom<IEnumerable<Item>>(okResult.Value);
        Assert.Single(returnedItems);
    }

    [Fact]
    public async Task GetItems_IncludesDescendants_WhenFlagIsTrue()
    {
        // Arrange
        var categories = new List<Category>
        {
            new() { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Parent", ParentCategoryId = null },
            new() { Id = 2, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Child", ParentCategoryId = 1 }
        };
        var items = new List<Item>
        {
            new() { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Item 1", CategoryId = 1 },
            new() { Id = 2, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Item 2", CategoryId = 2 }
        };

        _mockCategoryRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(categories);
        _mockItemRepository.Setup(repo => repo.GetByCategoryIdsAsync(It.IsAny<IEnumerable<int>>(), TestTenantId))
            .ReturnsAsync(items);

        // Act
        var result = await _controller.GetItems(categoryId: 1, includeDescendants: true);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        _mockItemRepository.Verify(repo => repo.GetByCategoryIdsAsync(
            It.Is<IEnumerable<int>>(ids => ids.Contains(1) && ids.Contains(2)),
            TestTenantId), Times.Once);
    }

    [Fact]
    public async Task GetItems_Returns304_WhenETagMatches()
    {
        // Arrange
        var items = new List<Item>
        {
            new() { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Item 1", CategoryId = TestCategoryId }
        };
        _mockItemRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(items);

        // First call to get the ETag
        var firstResult = await _controller.GetItems();
        var etag = _controller.Response.Headers.ETag.ToString();

        // Set up request with If-None-Match header
        _controller.ControllerContext.HttpContext.Request.Headers.IfNoneMatch = etag;

        // Act - second call with matching ETag
        var result = await _controller.GetItems();

        // Assert
        var statusResult = Assert.IsType<StatusCodeResult>(result.Result);
        Assert.Equal(304, statusResult.StatusCode);
    }

    #endregion

    #region GetItem Tests

    [Fact]
    public async Task GetItem_ReturnsOkResult_WhenItemExists()
    {
        // Arrange
        var item = new Item { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Test Item" };
        _mockItemRepository.Setup(repo => repo.GetByIdAsync(1, TestTenantId))
            .ReturnsAsync(item);

        // Act
        var result = await _controller.GetItem(1);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedItem = Assert.IsType<Item>(okResult.Value);
        Assert.Equal("Test Item", returnedItem.Name);
    }

    [Fact]
    public async Task GetItem_ReturnsNotFound_WhenItemDoesNotExist()
    {
        // Arrange
        _mockItemRepository.Setup(repo => repo.GetByIdAsync(999, TestTenantId))
            .ReturnsAsync((Item?)null);

        // Act
        var result = await _controller.GetItem(999);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    #endregion

    #region CreateItem Tests

    [Fact]
    public async Task CreateItem_ReturnsCreatedAtAction_WithNewItem()
    {
        // Arrange
        var request = new CreateItemRequest
        {
            Name = "New Item",
            Summary = "Summary",
            Description = "Description",
            CategoryId = TestCategoryId,
            CollectionId = TestCollectionId
        };
        var createdItem = new Item
        {
            Id = 1,
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Name = "New Item",
            Summary = "Summary",
            Description = "Description",
            CategoryId = TestCategoryId
        };
        var collection = new Collection { Id = TestCollectionId, TenantId = TestTenantId, Name = "Test Collection" };
        var category = new Category { Id = TestCategoryId, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Test Category" };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestTenantId))
            .ReturnsAsync(collection);
        _mockCategoryRepository.Setup(repo => repo.GetByIdAsync(TestCategoryId, TestTenantId))
            .ReturnsAsync(category);
        _mockItemRepository.Setup(repo => repo.CreateAsync(It.IsAny<Item>()))
            .ReturnsAsync(createdItem);

        // Act
        var result = await _controller.CreateItem(request);

        // Assert
        var createdResult = Assert.IsType<CreatedAtActionResult>(result.Result);
        Assert.Equal(nameof(_controller.GetItem), createdResult.ActionName);
        var returnedItem = Assert.IsType<Item>(createdResult.Value);
        Assert.Equal("New Item", returnedItem.Name);
    }

    #endregion

    #region UpdateItem Tests

    [Fact]
    public async Task UpdateItem_ReturnsOkResult_WhenItemExists()
    {
        // Arrange
        var request = new UpdateItemRequest
        {
            Name = "Updated Item",
            Summary = "Updated Summary",
            Description = "Updated Description",
            CategoryId = TestCategoryId,
            CollectionId = TestCollectionId
        };
        var updatedItem = new Item
        {
            Id = 1,
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Name = "Updated Item",
            Summary = "Updated Summary",
            Description = "Updated Description",
            CategoryId = TestCategoryId
        };
        var collection = new Collection { Id = TestCollectionId, TenantId = TestTenantId, Name = "Test Collection" };
        var category = new Category { Id = TestCategoryId, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Test Category" };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestTenantId))
            .ReturnsAsync(collection);
        _mockCategoryRepository.Setup(repo => repo.GetByIdAsync(TestCategoryId, TestTenantId))
            .ReturnsAsync(category);
        _mockItemRepository.Setup(repo => repo.UpdateAsync(1, It.IsAny<Item>(), TestTenantId))
            .ReturnsAsync(updatedItem);

        // Act
        var result = await _controller.UpdateItem(1, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedItem = Assert.IsType<Item>(okResult.Value);
        Assert.Equal("Updated Item", returnedItem.Name);
    }

    [Fact]
    public async Task UpdateItem_ReturnsNotFound_WhenItemDoesNotExist()
    {
        // Arrange
        var request = new UpdateItemRequest
        {
            Name = "Updated Item",
            CollectionId = TestCollectionId
        };
        var collection = new Collection { Id = TestCollectionId, TenantId = TestTenantId, Name = "Test Collection" };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestTenantId))
            .ReturnsAsync(collection);
        _mockItemRepository.Setup(repo => repo.UpdateAsync(999, It.IsAny<Item>(), TestTenantId))
            .ReturnsAsync((Item?)null);

        // Act
        var result = await _controller.UpdateItem(999, request);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    #endregion

    #region DeleteItem Tests

    [Fact]
    public async Task DeleteItem_ReturnsNoContent_WhenItemExists()
    {
        // Arrange
        _mockItemRepository.Setup(repo => repo.DeleteAsync(1, TestTenantId))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.DeleteItem(1);

        // Assert
        Assert.IsType<NoContentResult>(result);
    }

    [Fact]
    public async Task DeleteItem_ReturnsNotFound_WhenItemDoesNotExist()
    {
        // Arrange
        _mockItemRepository.Setup(repo => repo.DeleteAsync(999, TestTenantId))
            .ReturnsAsync(false);

        // Act
        var result = await _controller.DeleteItem(999);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    #endregion

    #region Security Tests

    [Fact]
    public async Task CreateItem_ReturnsBadRequest_WhenCollectionNotOwnedByTenant()
    {
        // Arrange - Collection returns null (not found for tenant)
        var request = new CreateItemRequest
        {
            Name = "New Item",
            CollectionId = 999  // Collection that doesn't belong to tenant
        };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(999, TestTenantId))
            .ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.CreateItem(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    [Fact]
    public async Task CreateItem_ReturnsBadRequest_WhenCategoryNotOwnedByTenant()
    {
        // Arrange - Collection is valid but Category is not
        var request = new CreateItemRequest
        {
            Name = "New Item",
            CollectionId = TestCollectionId,
            CategoryId = 999  // Category that doesn't belong to tenant
        };
        var collection = new Collection { Id = TestCollectionId, TenantId = TestTenantId, Name = "Test Collection" };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestTenantId))
            .ReturnsAsync(collection);
        _mockCategoryRepository.Setup(repo => repo.GetByIdAsync(999, TestTenantId))
            .ReturnsAsync((Category?)null);

        // Act
        var result = await _controller.CreateItem(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    [Fact]
    public async Task CreateItem_ReturnsBadRequest_WhenCategoryBelongsToDifferentCollection()
    {
        // Arrange - Category exists but belongs to different collection
        var request = new CreateItemRequest
        {
            Name = "New Item",
            CollectionId = TestCollectionId,
            CategoryId = TestCategoryId
        };
        var collection = new Collection { Id = TestCollectionId, TenantId = TestTenantId, Name = "Test Collection" };
        var category = new Category { Id = TestCategoryId, TenantId = TestTenantId, CollectionId = 999, Name = "Test Category" }; // Different CollectionId

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestTenantId))
            .ReturnsAsync(collection);
        _mockCategoryRepository.Setup(repo => repo.GetByIdAsync(TestCategoryId, TestTenantId))
            .ReturnsAsync(category);

        // Act
        var result = await _controller.CreateItem(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    [Fact]
    public async Task UpdateItem_ReturnsBadRequest_WhenCollectionNotOwnedByTenant()
    {
        // Arrange
        var request = new UpdateItemRequest
        {
            Name = "Updated Item",
            CollectionId = 999  // Collection that doesn't belong to tenant
        };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(999, TestTenantId))
            .ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.UpdateItem(1, request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    #endregion
}
