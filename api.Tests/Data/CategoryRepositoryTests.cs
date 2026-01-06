using api.Data;
using api.Models;
using Microsoft.EntityFrameworkCore;

namespace api.Tests.Data;

public class CategoryRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly CategoryRepository _repository;

    public CategoryRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _repository = new CategoryRepository(_context);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    #region GetAllAsync Tests

    [Fact]
    public async Task GetAllAsync_ReturnsAllCategories()
    {
        // Arrange
        var categories = new List<Category>
        {
            new() { Id = 1, TenantId = 1, Name = "Category 1", Description = "Desc 1" },
            new() { Id = 2, TenantId = 1, Name = "Category 2", Description = "Desc 2" }
        };
        await _context.Categories.AddRangeAsync(categories);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetAllAsync();

        // Assert
        Assert.Equal(2, result.Count());
    }

    [Fact]
    public async Task GetAllAsync_ReturnsEmptyList_WhenNoCategories()
    {
        // Act
        var result = await _repository.GetAllAsync();

        // Assert
        Assert.Empty(result);
    }

    #endregion

    #region GetByIdAsync Tests

    [Fact]
    public async Task GetByIdAsync_ReturnsCategory_WhenExists()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = 1, Name = "Test Category", Description = "Test Desc" };
        await _context.Categories.AddAsync(category);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(1);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Test Category", result.Name);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenNotExists()
    {
        // Act
        var result = await _repository.GetByIdAsync(999);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region CreateAsync Tests

    [Fact]
    public async Task CreateAsync_AddsCategory_AndReturnsIt()
    {
        // Arrange
        var category = new Category { TenantId = 1, Name = "New Category", Description = "New Desc" };

        // Act
        var result = await _repository.CreateAsync(category);

        // Assert
        Assert.NotNull(result);
        Assert.True(result.Id > 0);
        Assert.Equal("New Category", result.Name);

        // Verify it was saved
        var savedCategory = await _context.Categories.FindAsync(result.Id);
        Assert.NotNull(savedCategory);
    }

    [Fact]
    public async Task CreateAsync_WithParentCategory_SetsRelationship()
    {
        // Arrange
        var parentCategory = new Category { Id = 1, TenantId = 1, Name = "Parent", Description = "Parent Desc" };
        await _context.Categories.AddAsync(parentCategory);
        await _context.SaveChangesAsync();

        var childCategory = new Category { TenantId = 1, Name = "Child", Description = "Child Desc", ParentCategoryId = 1 };

        // Act
        var result = await _repository.CreateAsync(childCategory);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(1, result.ParentCategoryId);
    }

    #endregion

    #region UpdateAsync Tests

    [Fact]
    public async Task UpdateAsync_UpdatesCategory_WhenExists()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = 1, Name = "Original", Description = "Original Desc" };
        await _context.Categories.AddAsync(category);
        await _context.SaveChangesAsync();
        _context.Entry(category).State = EntityState.Detached;

        var updatedCategory = new Category { TenantId = 2, Name = "Updated", Description = "Updated Desc", ParentCategoryId = null };

        // Act
        var result = await _repository.UpdateAsync(1, updatedCategory);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Updated", result.Name);
        Assert.Equal("Updated Desc", result.Description);
        Assert.Equal(2, result.TenantId);
    }

    [Fact]
    public async Task UpdateAsync_ReturnsNull_WhenNotExists()
    {
        // Arrange
        var updatedCategory = new Category { TenantId = 1, Name = "Updated", Description = "Updated Desc" };

        // Act
        var result = await _repository.UpdateAsync(999, updatedCategory);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region DeleteAsync Tests

    [Fact]
    public async Task DeleteAsync_RemovesCategory_AndReturnsTrue()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = 1, Name = "To Delete", Description = "Delete Desc" };
        await _context.Categories.AddAsync(category);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.DeleteAsync(1);

        // Assert
        Assert.True(result);
        var deletedCategory = await _context.Categories.FindAsync(1);
        Assert.Null(deletedCategory);
    }

    [Fact]
    public async Task DeleteAsync_ReturnsFalse_WhenNotExists()
    {
        // Act
        var result = await _repository.DeleteAsync(999);

        // Assert
        Assert.False(result);
    }

    #endregion
}

