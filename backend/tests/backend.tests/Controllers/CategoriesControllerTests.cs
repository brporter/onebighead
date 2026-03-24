using OneBigHead.Server.Controllers;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Security.Claims;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class CategoriesControllerTests
{
    private readonly Mock<ICategoryRepository> _mockRepository;
    private readonly Mock<ICollectionRepository> _mockCollectionRepository;
    private readonly Mock<IVisibilityService> _mockVisibilityService;
    private readonly CategoriesController _controller;
    private const int TestWorkspaceId = 1;
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
        
        // Set up authenticated user context with workspace_id claim
        var claims = new List<Claim>
        {
            new("workspace_id", TestWorkspaceId.ToString()),
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
            new() { Id = 1, WorkspaceId = 1, CollectionId = 1, Name = "Category 1", Description = "Desc 1" },
            new() { Id = 2, WorkspaceId = 1, CollectionId = 1, Name = "Category 2", Description = "Desc 2" }
        };
        _mockRepository.Setup(repo => repo.GetAllAsync(TestWorkspaceId))
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
        _mockRepository.Setup(repo => repo.GetAllAsync(TestWorkspaceId))
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
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test", Slug = "test" };
        var categories = new List<Category>
        {
            new() { Id = 1, WorkspaceId = 1, CollectionId = TestCollectionId, Name = "Category 1", Description = "Desc 1" }
        };
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(categories);
        _mockRepository.Setup(repo => repo.GetTemplateIdsByCategoryAsync(TestCollectionId, TestWorkspaceId))
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
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(999, TestWorkspaceId))
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
        var category = new Category { Id = 1, WorkspaceId = 1, CollectionId = 1, Name = "Test Category", Description = "Test Desc" };
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
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
        _mockRepository.Setup(repo => repo.GetByIdAsync(999, TestWorkspaceId))
            .ReturnsAsync((Category?)null);

        // Act
        var result = await _controller.GetCategory(999);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    #endregion

    #region GetCategoryTemplates Tests

    [Fact]
    public async Task GetCategoryTemplates_ReturnsOkResult_WithInheritedTemplateIds()
    {
        // Arrange
        var category = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Test Category", Description = "Test Desc" };
        var inheritedTemplateIds = new List<int> { 10, 20, 30 };
        
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(category);
        _mockRepository.Setup(repo => repo.GetInheritedTemplateIdsAsync(1, TestWorkspaceId))
            .ReturnsAsync(inheritedTemplateIds);

        // Act
        var result = await _controller.GetCategoryTemplates(1);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedIds = Assert.IsAssignableFrom<IEnumerable<int>>(okResult.Value);
        Assert.Equal(3, returnedIds.Count());
        Assert.Contains(10, returnedIds);
        Assert.Contains(20, returnedIds);
        Assert.Contains(30, returnedIds);
    }

    [Fact]
    public async Task GetCategoryTemplates_ReturnsOkResult_WithEmptyList_WhenNoTemplates()
    {
        // Arrange
        var category = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Test Category", Description = "Test Desc" };
        
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(category);
        _mockRepository.Setup(repo => repo.GetInheritedTemplateIdsAsync(1, TestWorkspaceId))
            .ReturnsAsync(new List<int>());

        // Act
        var result = await _controller.GetCategoryTemplates(1);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedIds = Assert.IsAssignableFrom<IEnumerable<int>>(okResult.Value);
        Assert.Empty(returnedIds);
    }

    [Fact]
    public async Task GetCategoryTemplates_ReturnsNotFound_WhenCategoryDoesNotExist()
    {
        // Arrange
        _mockRepository.Setup(repo => repo.GetByIdAsync(999, TestWorkspaceId))
            .ReturnsAsync((Category?)null);

        // Act
        var result = await _controller.GetCategoryTemplates(999);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    [Fact]
    public async Task GetCategoryTemplates_CallsGetInheritedTemplateIdsAsync()
    {
        // Arrange
        var category = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Test Category", Description = "Test Desc" };
        
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(category);
        _mockRepository.Setup(repo => repo.GetInheritedTemplateIdsAsync(1, TestWorkspaceId))
            .ReturnsAsync(new List<int> { 1, 2 });

        // Act
        await _controller.GetCategoryTemplates(1);

        // Assert
        _mockRepository.Verify(repo => repo.GetInheritedTemplateIdsAsync(1, TestWorkspaceId), Times.Once);
    }

    #endregion

    #region CreateCategory Tests

    [Fact]
    public async Task CreateCategory_ReturnsCreatedAtAction_WithNewCategory()
    {
        // Arrange
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test", Slug = "test" };
        var request = new CreateCategoryRequest { CollectionId = TestCollectionId, Name = "New Category", Description = "New Desc" };
        var createdCategory = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "New Category", Description = "New Desc" };
        
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.CreateAsync(It.Is<Category>(c => c.WorkspaceId == TestWorkspaceId)))
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
    public async Task CreateCategory_SetsWorkspaceIdFromClaims()
    {
        // Arrange
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test", Slug = "test" };
        var request = new CreateCategoryRequest { CollectionId = TestCollectionId, Name = "New Category", Description = "New Desc" };
        
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.CreateAsync(It.IsAny<Category>()))
            .ReturnsAsync((Category c) => new Category { Id = 1, WorkspaceId = c.WorkspaceId, CollectionId = c.CollectionId, Name = c.Name, Description = c.Description });

        // Act
        await _controller.CreateCategory(request);

        // Assert
        _mockRepository.Verify(repo => repo.CreateAsync(It.Is<Category>(c => c.WorkspaceId == TestWorkspaceId)), Times.Once);
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
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test", Slug = "test" };
        var request = new CreateCategoryRequest { CollectionId = TestCollectionId, Name = "New Category", Description = "Desc" };
        
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.CreateAsync(It.IsAny<Category>()))
            .ReturnsAsync((Category c) => new Category { Id = 1, WorkspaceId = c.WorkspaceId, CollectionId = c.CollectionId, Name = c.Name, Description = c.Description, IsSystem = c.IsSystem });

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
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(999, TestWorkspaceId))
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
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test", Slug = "test", Visibility = Visibility.Private };
        var existingCategory = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Original", Description = "Original Desc", IsSystem = false };
        var request = new UpdateCategoryRequest { Name = "Updated Category", Description = "Updated Desc" };
        var updatedCategory = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Updated Category", Description = "Updated Desc" };

        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(existingCategory);
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { existingCategory });
        _mockRepository.Setup(repo => repo.UpdateAsync(1, It.IsAny<Category>(), TestWorkspaceId))
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
        _mockRepository.Setup(repo => repo.GetByIdAsync(999, TestWorkspaceId))
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
        var systemCategory = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Unassigned Items", Description = "System", IsSystem = true };
        var request = new UpdateCategoryRequest { Name = "Try to Update", Description = "Updated Desc" };
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
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
        var existingCategory = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Original", Description = "Original Desc", IsSystem = false };
        var request = new UpdateCategoryRequest { Name = "Unassigned Items", Description = "Updated Desc" };
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
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
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test", Slug = "test", Visibility = Visibility.Private };
        var existingCategory = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Original", Description = "Original Desc", IsSystem = false };
        var request = new UpdateCategoryRequest { Name = "Updated", Description = "Updated Desc" };
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(existingCategory);
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { existingCategory });
        _mockRepository.Setup(repo => repo.UpdateAsync(1, It.IsAny<Category>(), TestWorkspaceId))
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
        var existingCategory = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "To Delete", Description = "Desc", IsSystem = false };
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(existingCategory);
        _mockRepository.Setup(repo => repo.DeleteAsync(1, TestWorkspaceId))
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
        _mockRepository.Setup(repo => repo.GetByIdAsync(999, TestWorkspaceId))
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
        var systemCategory = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Unassigned Items", Description = "System", IsSystem = true };
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
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
        var existingCategory = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "To Delete", Description = "Desc", IsSystem = false };
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(existingCategory);
        _mockRepository.Setup(repo => repo.DeleteAsync(1, TestWorkspaceId))
            .ReturnsAsync(false);

        // Act
        var result = await _controller.DeleteCategory(1);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    #endregion

    #region Visibility Default Tests

    [Fact]
    public async Task CreateCategory_DefaultsToCollectionVisibility_WhenNoParent()
    {
        // Arrange
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Public Collection", Slug = "test", Visibility = Visibility.Public };
        var request = new CreateCategoryRequest { CollectionId = TestCollectionId, Name = "New Category" };

        Category? capturedCategory = null;
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category>());
        _mockRepository.Setup(repo => repo.CreateAsync(It.IsAny<Category>()))
            .Callback<Category>(c => capturedCategory = c)
            .ReturnsAsync((Category c) => new Category { Id = 1, WorkspaceId = c.WorkspaceId, CollectionId = c.CollectionId, Name = c.Name, Visibility = c.Visibility });

        // Act
        await _controller.CreateCategory(request);

        // Assert
        Assert.NotNull(capturedCategory);
        Assert.Equal(Visibility.Public, capturedCategory!.Visibility);
    }

    [Fact]
    public async Task CreateCategory_DefaultsToParentVisibility()
    {
        // Arrange
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Public Collection", Slug = "test", Visibility = Visibility.Public };
        var parentCategory = new Category { Id = 10, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Private Parent", Visibility = Visibility.Private, EffectiveIsPublic = false };
        var request = new CreateCategoryRequest { CollectionId = TestCollectionId, Name = "Child Category", ParentCategoryId = 10 };

        Category? capturedCategory = null;
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { parentCategory });
        _mockRepository.Setup(repo => repo.CreateAsync(It.IsAny<Category>()))
            .Callback<Category>(c => capturedCategory = c)
            .ReturnsAsync((Category c) => new Category { Id = 2, WorkspaceId = c.WorkspaceId, CollectionId = c.CollectionId, Name = c.Name, Visibility = c.Visibility });

        // Act
        await _controller.CreateCategory(request);

        // Assert
        Assert.NotNull(capturedCategory);
        Assert.Equal(Visibility.Private, capturedCategory!.Visibility);
    }

    [Fact]
    public async Task UpdateCategory_PreservesExistingVisibility()
    {
        // Arrange
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test", Slug = "test", Visibility = Visibility.Private };
        var existingCategory = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Original", IsSystem = false, Visibility = Visibility.Public };
        var request = new UpdateCategoryRequest { Name = "Updated Category", Description = "Updated Desc" };

        Category? capturedCategory = null;
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(existingCategory);
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { existingCategory });
        _mockRepository.Setup(repo => repo.UpdateAsync(1, It.IsAny<Category>(), TestWorkspaceId))
            .Callback<int, Category, int>((id, c, ws) => capturedCategory = c)
            .ReturnsAsync((int id, Category c, int ws) => new Category { Id = id, WorkspaceId = ws, Name = c.Name, Visibility = c.Visibility });

        // Act
        await _controller.UpdateCategory(1, request);

        // Assert - Visibility should be preserved from existing category (Public)
        Assert.NotNull(capturedCategory);
        Assert.Equal(Visibility.Public, capturedCategory!.Visibility);
    }

    #endregion

    #region Security Tests

    [Fact]
    public async Task CreateCategory_ReturnsBadRequest_WhenParentCategoryNotOwnedByWorkspace()
    {
        // Arrange
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test Collection" };
        var request = new CreateCategoryRequest
        {
            Name = "New Category",
            CollectionId = TestCollectionId,
            ParentCategoryId = 999  // Parent that doesn't belong to workspace
        };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.GetByIdAsync(999, TestWorkspaceId))
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
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test Collection" };
        var parentCategory = new Category { Id = 99, WorkspaceId = TestWorkspaceId, CollectionId = 999, Name = "Parent in different collection" }; // Different collection
        var request = new CreateCategoryRequest
        {
            Name = "New Category",
            CollectionId = TestCollectionId,
            ParentCategoryId = 99
        };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.GetByIdAsync(99, TestWorkspaceId))
            .ReturnsAsync(parentCategory);

        // Act
        var result = await _controller.CreateCategory(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    [Fact]
    public async Task UpdateCategory_ReturnsBadRequest_WhenParentCategoryNotOwnedByWorkspace()
    {
        // Arrange
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test", Slug = "test", Visibility = Visibility.Private };
        var existingCategory = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Existing", IsSystem = false };
        var request = new UpdateCategoryRequest
        {
            Name = "Updated",
            ParentCategoryId = 999  // Parent that doesn't belong to workspace
        };

        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(existingCategory);
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { existingCategory });

        // Act
        var result = await _controller.UpdateCategory(1, request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    [Fact]
    public async Task UpdateCategory_ReturnsBadRequest_WhenParentCategoryBelongsToDifferentCollection()
    {
        // Arrange
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test", Slug = "test", Visibility = Visibility.Private };
        var existingCategory = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Existing", IsSystem = false };
        var request = new UpdateCategoryRequest
        {
            Name = "Updated",
            ParentCategoryId = 99  // Parent in different collection - won't be in categoryLookup
        };

        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(existingCategory);
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { existingCategory }); // Parent not in this collection's categories

        // Act
        var result = await _controller.UpdateCategory(1, request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    #endregion
}

