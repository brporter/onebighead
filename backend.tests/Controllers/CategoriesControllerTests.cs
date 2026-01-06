using backend.Controllers;
using backend.Data;
using backend.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Security.Claims;

namespace backend.Tests.Controllers;

public class CategoriesControllerTests
{
    private readonly Mock<ICategoryRepository> _mockRepository;
    private readonly CategoriesController _controller;
    private const int TestTenantId = 1;

    public CategoriesControllerTests()
    {
        _mockRepository = new Mock<ICategoryRepository>();
        _controller = new CategoriesController(_mockRepository.Object);
        
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
            new() { Id = 1, TenantId = 1, Name = "Category 1", Description = "Desc 1" },
            new() { Id = 2, TenantId = 1, Name = "Category 2", Description = "Desc 2" }
        };
        _mockRepository.Setup(repo => repo.GetAllAsync(TestTenantId))
            .ReturnsAsync(categories);

        // Act
        var result = await _controller.GetCategories();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCategories = Assert.IsAssignableFrom<IEnumerable<Category>>(okResult.Value);
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
        var returnedCategories = Assert.IsAssignableFrom<IEnumerable<Category>>(okResult.Value);
        Assert.Empty(returnedCategories);
    }

    #endregion

    #region GetCategory Tests

    [Fact]
    public async Task GetCategory_ReturnsOkResult_WhenCategoryExists()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = 1, Name = "Test Category", Description = "Test Desc" };
        _mockRepository.Setup(repo => repo.GetByIdAsync(1, TestTenantId))
            .ReturnsAsync(category);

        // Act
        var result = await _controller.GetCategory(1);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCategory = Assert.IsType<Category>(okResult.Value);
        Assert.Equal(1, returnedCategory.Id);
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
        var newCategory = new Category { Name = "New Category", Description = "New Desc" };
        var createdCategory = new Category { Id = 1, TenantId = TestTenantId, Name = "New Category", Description = "New Desc" };
        _mockRepository.Setup(repo => repo.CreateAsync(It.Is<Category>(c => c.TenantId == TestTenantId)))
            .ReturnsAsync(createdCategory);

        // Act
        var result = await _controller.CreateCategory(newCategory);

        // Assert
        var createdAtActionResult = Assert.IsType<CreatedAtActionResult>(result.Result);
        Assert.Equal(nameof(CategoriesController.GetCategory), createdAtActionResult.ActionName);
        Assert.Equal(1, createdAtActionResult.RouteValues?["id"]);
        var returnedCategory = Assert.IsType<Category>(createdAtActionResult.Value);
        Assert.Equal("New Category", returnedCategory.Name);
    }

    [Fact]
    public async Task CreateCategory_SetsTenantIdFromClaims()
    {
        // Arrange
        var newCategory = new Category { Name = "New Category", Description = "New Desc" };
        _mockRepository.Setup(repo => repo.CreateAsync(It.IsAny<Category>()))
            .ReturnsAsync((Category c) => new Category { Id = 1, TenantId = c.TenantId, Name = c.Name, Description = c.Description });

        // Act
        await _controller.CreateCategory(newCategory);

        // Assert
        _mockRepository.Verify(repo => repo.CreateAsync(It.Is<Category>(c => c.TenantId == TestTenantId)), Times.Once);
    }

    #endregion

    #region UpdateCategory Tests

    [Fact]
    public async Task UpdateCategory_ReturnsOkResult_WhenCategoryExists()
    {
        // Arrange
        var updatedCategory = new Category { Id = 1, TenantId = 1, Name = "Updated Category", Description = "Updated Desc" };
        _mockRepository.Setup(repo => repo.UpdateAsync(1, updatedCategory, TestTenantId))
            .ReturnsAsync(updatedCategory);

        // Act
        var result = await _controller.UpdateCategory(1, updatedCategory);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCategory = Assert.IsType<Category>(okResult.Value);
        Assert.Equal("Updated Category", returnedCategory.Name);
    }

    [Fact]
    public async Task UpdateCategory_ReturnsNotFound_WhenCategoryDoesNotExist()
    {
        // Arrange
        var updatedCategory = new Category { Id = 999, TenantId = 1, Name = "Updated Category", Description = "Updated Desc" };
        _mockRepository.Setup(repo => repo.UpdateAsync(999, updatedCategory, TestTenantId))
            .ReturnsAsync((Category?)null);

        // Act
        var result = await _controller.UpdateCategory(999, updatedCategory);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    #endregion

    #region DeleteCategory Tests

    [Fact]
    public async Task DeleteCategory_ReturnsNoContent_WhenCategoryExists()
    {
        // Arrange
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
        _mockRepository.Setup(repo => repo.DeleteAsync(999, TestTenantId))
            .ReturnsAsync(false);

        // Act
        var result = await _controller.DeleteCategory(999);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    #endregion
}

