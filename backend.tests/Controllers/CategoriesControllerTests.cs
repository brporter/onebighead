using backend.Controllers;
using backend.Data;
using backend.Models;
using backend.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Security.Claims;

namespace backend.Tests.Controllers;

public class CategoriesControllerTests
{
    private readonly Mock<ICategoryRepository> _mockRepository;
    private readonly Mock<ICollectionRepository> _mockCollectionRepository;
    private readonly Mock<IVisibilityService> _mockVisibilityService;
    private readonly CategoriesController _controller;
    private const int TestTenantId = 1;
    private const int TestCollectionId = 1;

    public CategoriesControllerTests()
    {
        _mockRepository = new Mock<ICategoryRepository>();
        _mockCollectionRepository = new Mock<ICollectionRepository>();
        _mockVisibilityService = new Mock<IVisibilityService>();
        _controller = new CategoriesController(
            _mockRepository.Object, 
            _mockCollectionRepository.Object,
            _mockVisibilityService.Object);
        
        // Set up authenticated user context with tenant_id claim
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

    #region GetCategories Tests

    [Fact]
    public async Task GetCategories_ReturnsOkResult_WithListOfCategories()
    {
        // Arrange
        var categories = new List<Category>
        {
            new() { Id = 1, TenantId = 1, CollectionId = 1, Name = "Category 1", Description = "Desc 1" },
            new() { Id = 2, TenantId = 1, CollectionId = 1, Name = "Category 2", Description = "Desc 2" }
        };
        _mockRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(categories);

        // Act
        var result = await _controller.GetCategories();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCategories = Assert.IsAssignableFrom<IEnumerable<CategoryResponse>>(okResult.Value);
        Assert.Equal(2, returnedCategories.Count());
    }

    [Fact]
    public async Task GetCategories_ReturnsOkResult_WithEmptyList_WhenNoCategories()
    {
        // Arrange
        _mockRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(new List<Category>());

        // Act
        var result = await _controller.GetCategories();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCategories = Assert.IsAssignableFrom<IEnumerable<CategoryResponse>>(okResult.Value);
        Assert.Empty(returnedCategories);
    }

    [Fact]
    public async Task GetCategories_WithCollectionId_ReturnsFilteredCategories()
    {
        // Arrange
        var collection = new Collection { Id = TestCollectionId, TenantId = TestTenantId, Name = "Test", Slug = "test" };
        var categories = new List<Category>
        {
            new() { Id = 1, TenantId = 1, CollectionId = TestCollectionId, Name = "Category 1", Description = "Desc 1" }
        };
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestTenantId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestTenantId))
            .ReturnsAsync(categories);
        _mockRepository.Setup(repo => repo.GetTemplateIdsByCategoryAsync(TestCollectionId, TestTenantId))
            .ReturnsAsync(new Dictionary<int, List<int>>());

        // Act
        var result = await _controller.GetCategories(TestCollectionId);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCategories = Assert.IsAssignableFrom<IEnumerable<CategoryResponse>>(okResult.Value);
        Assert.Single(returnedCategories);
    }

    [Fact]
    public async Task GetCategories_WithInvalidCollectionId_ReturnsNotFound()
    {
        // Arrange
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(999, TestTenantId))
            .ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.GetCategories(999);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result.Result);
    }

    #endregion

    #region GetCategory Tests

    [Fact]
    public async Task GetCategory_ReturnsOkResult_WhenCategoryExists()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = 1, CollectionId = 1, Name = "Test Category", Description = "Test Desc" };
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestTenantId))
            .ReturnsAsync(category);

        // Act
        var result = await _controller.GetCategory(1);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCategory = Assert.IsType<CategoryResponse>(okResult.Value);
        Assert.Equal(1, returnedCategory.CategoryId);
        Assert.Equal("Test Category", returnedCategory.Name);
    }

    [Fact]
    public async Task GetCategory_ReturnsNotFound_WhenCategoryDoesNotExist()
    {
        // Arrange
        _mockRepository.Setup(repo => repo.GetByIdAsync(999, TestTenantId))
            .ReturnsAsync((Category?)null);

        // Act
        var result = await _controller.GetCategory(999);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    #endregion

    #region CreateCategory Tests

    [Fact]
    public async Task CreateCategory_ReturnsCreatedAtAction_WithNewCategory()
    {
        // Arrange
        var collection = new Collection { Id = TestCollectionId, TenantId = TestTenantId, Name = "Test", Slug = "test" };
        var request = new CreateCategoryRequest { CollectionId = TestCollectionId, Name = "New Category", Description = "New Desc" };
        var createdCategory = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "New Category", Description = "New Desc" };
        
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestTenantId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.CreateAsync(It.Is<Category>(c => c.TenantId == TestTenantId)))
            .ReturnsAsync(createdCategory);

        // Act
        var result = await _controller.CreateCategory(request);

        // Assert
        var createdAtActionResult = Assert.IsType<CreatedAtActionResult>(result.Result);
        Assert.Equal(nameof(CategoriesController.GetCategory), createdAtActionResult.ActionName);
        Assert.Equal(1, createdAtActionResult.RouteValues?["id"]);
        var returnedCategory = Assert.IsType<CategoryResponse>(createdAtActionResult.Value);
        Assert.Equal("New Category", returnedCategory.Name);
    }

    [Fact]
    public async Task CreateCategory_SetsTenantIdFromClaims()
    {
        // Arrange
        var collection = new Collection { Id = TestCollectionId, TenantId = TestTenantId, Name = "Test", Slug = "test" };
        var request = new CreateCategoryRequest { CollectionId = TestCollectionId, Name = "New Category", Description = "New Desc" };
        
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestTenantId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.CreateAsync(It.IsAny<Category>()))
            .ReturnsAsync((Category c) => new Category { Id = 1, TenantId = c.TenantId, CollectionId = c.CollectionId, Name = c.Name, Description = c.Description });

        // Act
        await _controller.CreateCategory(request);

        // Assert
        _mockRepository.Verify(repo => repo.CreateAsync(It.Is<Category>(c => c.TenantId == TestTenantId)), Times.Once);
    }

    [Fact]
    public async Task CreateCategory_ReturnsBadRequest_WhenNameIsReserved()
    {
        // Arrange
        var request = new CreateCategoryRequest { CollectionId = TestCollectionId, Name = "Unassigned Items", Description = "Trying to use reserved name" };

        // Act
        var result = await _controller.CreateCategory(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    [Fact]
    public async Task CreateCategory_SetsIsSystemToFalse()
    {
        // Arrange
        var collection = new Collection { Id = TestCollectionId, TenantId = TestTenantId, Name = "Test", Slug = "test" };
        var request = new CreateCategoryRequest { CollectionId = TestCollectionId, Name = "New Category", Description = "Desc" };
        
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestTenantId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.CreateAsync(It.IsAny<Category>()))
            .ReturnsAsync((Category c) => new Category { Id = 1, TenantId = c.TenantId, CollectionId = c.CollectionId, Name = c.Name, Description = c.Description, IsSystem = c.IsSystem });

        // Act
        await _controller.CreateCategory(request);

        // Assert
        _mockRepository.Verify(repo => repo.CreateAsync(It.Is<Category>(c => c.IsSystem == false)), Times.Once);
    }

    [Fact]
    public async Task CreateCategory_ReturnsBadRequest_WhenCollectionNotFound()
    {
        // Arrange
        var request = new CreateCategoryRequest { CollectionId = 999, Name = "New Category", Description = "Desc" };
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(999, TestTenantId))
            .ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.CreateCategory(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    #endregion

    #region UpdateCategory Tests

    [Fact]
    public async Task UpdateCategory_ReturnsOkResult_WhenCategoryExists()
    {
        // Arrange
        var existingCategory = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Original", Description = "Original Desc", IsSystem = false };
        var request = new UpdateCategoryRequest { Name = "Updated Category", Description = "Updated Desc" };
        var updatedCategory = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Updated Category", Description = "Updated Desc" };
        
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestTenantId))
            .ReturnsAsync(existingCategory);
        _mockRepository.Setup(repo => repo.UpdateAsync(1, It.IsAny<Category>(), TestTenantId))
            .ReturnsAsync(updatedCategory);

        // Act
        var result = await _controller.UpdateCategory(1, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCategory = Assert.IsType<CategoryResponse>(okResult.Value);
        Assert.Equal("Updated Category", returnedCategory.Name);
    }

    [Fact]
    public async Task UpdateCategory_ReturnsNotFound_WhenCategoryDoesNotExist()
    {
        // Arrange
        var request = new UpdateCategoryRequest { Name = "Updated Category", Description = "Updated Desc" };
        _mockRepository.Setup(repo => repo.GetByIdAsync(999, TestTenantId))
            .ReturnsAsync((Category?)null);

        // Act
        var result = await _controller.UpdateCategory(999, request);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    [Fact]
    public async Task UpdateCategory_ReturnsForbidden_WhenCategoryIsSystem()
    {
        // Arrange
        var systemCategory = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Unassigned Items", Description = "System", IsSystem = true };
        var request = new UpdateCategoryRequest { Name = "Try to Update", Description = "Updated Desc" };
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestTenantId))
            .ReturnsAsync(systemCategory);

        // Act
        var result = await _controller.UpdateCategory(1, request);

        // Assert
        var objectResult = Assert.IsType<ObjectResult>(result.Result);
        Assert.Equal(403, objectResult.StatusCode);
    }

    [Fact]
    public async Task UpdateCategory_ReturnsBadRequest_WhenRenamingToReservedName()
    {
        // Arrange
        var existingCategory = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Original", Description = "Original Desc", IsSystem = false };
        var request = new UpdateCategoryRequest { Name = "Unassigned Items", Description = "Updated Desc" };
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestTenantId))
            .ReturnsAsync(existingCategory);

        // Act
        var result = await _controller.UpdateCategory(1, request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    [Fact]
    public async Task UpdateCategory_ReturnsNotFound_WhenUpdateReturnsNull()
    {
        // Arrange - simulates a race condition where category is deleted between get and update
        var existingCategory = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Original", Description = "Original Desc", IsSystem = false };
        var request = new UpdateCategoryRequest { Name = "Updated", Description = "Updated Desc" };
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestTenantId))
            .ReturnsAsync(existingCategory);
        _mockRepository.Setup(repo => repo.UpdateAsync(1, It.IsAny<Category>(), TestTenantId))
            .ReturnsAsync((Category?)null);

        // Act
        var result = await _controller.UpdateCategory(1, request);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    #endregion

    #region DeleteCategory Tests

    [Fact]
    public async Task DeleteCategory_ReturnsNoContent_WhenCategoryExists()
    {
        // Arrange
        var existingCategory = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "To Delete", Description = "Desc", IsSystem = false };
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestTenantId))
            .ReturnsAsync(existingCategory);
        _mockRepository.Setup(repo => repo.DeleteAsync(1, TestTenantId))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.DeleteCategory(1);

        // Assert
        Assert.IsType<NoContentResult>(result);
    }

    [Fact]
    public async Task DeleteCategory_ReturnsNotFound_WhenCategoryDoesNotExist()
    {
        // Arrange
        _mockRepository.Setup(repo => repo.GetByIdAsync(999, TestTenantId))
            .ReturnsAsync((Category?)null);

        // Act
        var result = await _controller.DeleteCategory(999);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task DeleteCategory_ReturnsForbidden_WhenCategoryIsSystem()
    {
        // Arrange
        var systemCategory = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Unassigned Items", Description = "System", IsSystem = true };
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestTenantId))
            .ReturnsAsync(systemCategory);

        // Act
        var result = await _controller.DeleteCategory(1);

        // Assert
        var objectResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(403, objectResult.StatusCode);
    }

    [Fact]
    public async Task DeleteCategory_ReturnsNotFound_WhenDeleteFails()
    {
        // Arrange - simulates a race condition where category is deleted between check and delete
        var existingCategory = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "To Delete", Description = "Desc", IsSystem = false };
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestTenantId))
            .ReturnsAsync(existingCategory);
        _mockRepository.Setup(repo => repo.DeleteAsync(1, TestTenantId))
            .ReturnsAsync(false);

        // Act
        var result = await _controller.DeleteCategory(1);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    #endregion

    #region Security Tests

    [Fact]
    public async Task CreateCategory_ReturnsBadRequest_WhenParentCategoryNotOwnedByTenant()
    {
        // Arrange
        var collection = new Collection { Id = TestCollectionId, TenantId = TestTenantId, Name = "Test Collection" };
        var request = new CreateCategoryRequest
        {
            Name = "New Category",
            CollectionId = TestCollectionId,
            ParentCategoryId = 999  // Parent that doesn't belong to tenant
        };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestTenantId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.GetByIdAsync(999, TestTenantId))
            .ReturnsAsync((Category?)null);

        // Act
        var result = await _controller.CreateCategory(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    [Fact]
    public async Task CreateCategory_ReturnsBadRequest_WhenParentCategoryBelongsToDifferentCollection()
    {
        // Arrange
        var collection = new Collection { Id = TestCollectionId, TenantId = TestTenantId, Name = "Test Collection" };
        var parentCategory = new Category { Id = 99, TenantId = TestTenantId, CollectionId = 999, Name = "Parent in different collection" }; // Different collection
        var request = new CreateCategoryRequest
        {
            Name = "New Category",
            CollectionId = TestCollectionId,
            ParentCategoryId = 99
        };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestTenantId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.GetByIdAsync(99, TestTenantId))
            .ReturnsAsync(parentCategory);

        // Act
        var result = await _controller.CreateCategory(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    [Fact]
    public async Task UpdateCategory_ReturnsBadRequest_WhenParentCategoryNotOwnedByTenant()
    {
        // Arrange
        var existingCategory = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Existing", IsSystem = false };
        var request = new UpdateCategoryRequest
        {
            Name = "Updated",
            ParentCategoryId = 999  // Parent that doesn't belong to tenant
        };

        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestTenantId))
            .ReturnsAsync(existingCategory);
        _mockRepository.Setup(repo => repo.GetByIdAsync(999, TestTenantId))
            .ReturnsAsync((Category?)null);

        // Act
        var result = await _controller.UpdateCategory(1, request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    [Fact]
    public async Task UpdateCategory_ReturnsBadRequest_WhenParentCategoryBelongsToDifferentCollection()
    {
        // Arrange
        var existingCategory = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Existing", IsSystem = false };
        var parentCategory = new Category { Id = 99, TenantId = TestTenantId, CollectionId = 999, Name = "Parent in different collection" }; // Different collection
        var request = new UpdateCategoryRequest
        {
            Name = "Updated",
            ParentCategoryId = 99
        };

        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestTenantId))
            .ReturnsAsync(existingCategory);
        _mockRepository.Setup(repo => repo.GetByIdAsync(99, TestTenantId))
            .ReturnsAsync(parentCategory);

        // Act
        var result = await _controller.UpdateCategory(1, request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    #endregion
}

