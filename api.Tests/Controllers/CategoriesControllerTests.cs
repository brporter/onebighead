using api.Controllers;
using api.Data;
using api.Models;
using Microsoft.AspNetCore.Mvc;
using Moq;

namespace api.Tests.Controllers;

public class CategoriesControllerTests
{
    private readonly Mock<ICategoryRepository> _mockRepository;
    private readonly CategoriesController _controller;

    public CategoriesControllerTests()
    {
        _mockRepository = new Mock<ICategoryRepository>();
        _controller = new CategoriesController(_mockRepository.Object);
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
        _mockRepository.Setup(repo => repo.GetAllAsync())
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
        _mockRepository.Setup(repo => repo.GetAllAsync())
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
        _mockRepository.Setup(repo => repo.GetByIdAsync(1))
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
        _mockRepository.Setup(repo => repo.GetByIdAsync(999))
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
        var newCategory = new Category { TenantId = 1, Name = "New Category", Description = "New Desc" };
        var createdCategory = new Category { Id = 1, TenantId = 1, Name = "New Category", Description = "New Desc" };
        _mockRepository.Setup(repo => repo.CreateAsync(newCategory))
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
    public async Task CreateCategory_CallsRepositoryCreate()
    {
        // Arrange
        var newCategory = new Category { TenantId = 1, Name = "New Category", Description = "New Desc" };
        _mockRepository.Setup(repo => repo.CreateAsync(It.IsAny<Category>()))
            .ReturnsAsync(new Category { Id = 1, TenantId = 1, Name = "New Category", Description = "New Desc" });

        // Act
        await _controller.CreateCategory(newCategory);

        // Assert
        _mockRepository.Verify(repo => repo.CreateAsync(newCategory), Times.Once);
    }

    #endregion

    #region UpdateCategory Tests

    [Fact]
    public async Task UpdateCategory_ReturnsOkResult_WhenCategoryExists()
    {
        // Arrange
        var updatedCategory = new Category { Id = 1, TenantId = 1, Name = "Updated Category", Description = "Updated Desc" };
        _mockRepository.Setup(repo => repo.UpdateAsync(1, updatedCategory))
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
        _mockRepository.Setup(repo => repo.UpdateAsync(999, updatedCategory))
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
        _mockRepository.Setup(repo => repo.DeleteAsync(1))
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
        _mockRepository.Setup(repo => repo.DeleteAsync(999))
            .ReturnsAsync(false);

        // Act
        var result = await _controller.DeleteCategory(999);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    #endregion
}

