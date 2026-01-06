using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Tests.Data;

public class CategoryRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly CategoryRepository _repository;
    private const int TestTenantId = 1;
    private const int OtherTenantId = 2;

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
    public async Task GetAllAsync_ReturnsOnlyCategoriesForTenant()
    {
        // Arrange
        var categories = new List<Category>
        {
            new() { Id = 1, TenantId = TestTenantId, Name = "Category 1", Description = "Desc 1" },
            new() { Id = 2, TenantId = TestTenantId, Name = "Category 2", Description = "Desc 2" },
            new() { Id = 3, TenantId = OtherTenantId, Name = "Category 3", Description = "Desc 3" }
        };
        await _context.Categories.AddRangeAsync(categories);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetAllAsync(TestTenantId);

        // Assert
        Assert.Equal(2, result.Count());
        Assert.All(result, c => Assert.Equal(TestTenantId, c.TenantId));
    }

    [Fact]
    public async Task GetAllAsync_ReturnsEmptyList_WhenNoCategories()
    {
        // Act
        var result = await _repository.GetAllAsync(TestTenantId);

        // Assert
        Assert.Empty(result);
    }

    #endregion

    #region GetByIdAsync Tests

    [Fact]
    public async Task GetByIdAsync_ReturnsCategory_WhenExistsForTenant()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = TestTenantId, Name = "Test Category", Description = "Test Desc" };
        await _context.Categories.AddAsync(category);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(1, TestTenantId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Test Category", result.Name);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenNotExists()
    {
        // Act
        var result = await _repository.GetByIdAsync(999, TestTenantId);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenExistsButDifferentTenant()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = OtherTenantId, Name = "Test Category", Description = "Test Desc" };
        await _context.Categories.AddAsync(category);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(1, TestTenantId);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region CreateAsync Tests

    [Fact]
    public async Task CreateAsync_AddsCategory_AndReturnsIt()
    {
        // Arrange
        var category = new Category { TenantId = TestTenantId, Name = "New Category", Description = "New Desc" };

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
        var parentCategory = new Category { Id = 1, TenantId = TestTenantId, Name = "Parent", Description = "Parent Desc" };
        await _context.Categories.AddAsync(parentCategory);
        await _context.SaveChangesAsync();

        var childCategory = new Category { TenantId = TestTenantId, Name = "Child", Description = "Child Desc", ParentCategoryId = 1 };

        // Act
        var result = await _repository.CreateAsync(childCategory);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(1, result.ParentCategoryId);
    }

    #endregion

    #region UpdateAsync Tests

    [Fact]
    public async Task UpdateAsync_UpdatesCategory_WhenExistsForTenant()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = TestTenantId, Name = "Original", Description = "Original Desc" };
        await _context.Categories.AddAsync(category);
        await _context.SaveChangesAsync();
        _context.Entry(category).State = EntityState.Detached;

        var updatedCategory = new Category { Name = "Updated", Description = "Updated Desc", ParentCategoryId = null };

        // Act
        var result = await _repository.UpdateAsync(1, updatedCategory, TestTenantId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Updated", result.Name);
        Assert.Equal("Updated Desc", result.Description);
        Assert.Equal(TestTenantId, result.TenantId); // TenantId should not change
    }

    [Fact]
    public async Task UpdateAsync_ReturnsNull_WhenNotExists()
    {
        // Arrange
        var updatedCategory = new Category { Name = "Updated", Description = "Updated Desc" };

        // Act
        var result = await _repository.UpdateAsync(999, updatedCategory, TestTenantId);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task UpdateAsync_ReturnsNull_WhenExistsButDifferentTenant()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = OtherTenantId, Name = "Original", Description = "Original Desc" };
        await _context.Categories.AddAsync(category);
        await _context.SaveChangesAsync();
        _context.Entry(category).State = EntityState.Detached;

        var updatedCategory = new Category { Name = "Updated", Description = "Updated Desc" };

        // Act
        var result = await _repository.UpdateAsync(1, updatedCategory, TestTenantId);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region DeleteAsync Tests

    [Fact]
    public async Task DeleteAsync_RemovesCategory_AndReturnsTrue()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = TestTenantId, Name = "To Delete", Description = "Delete Desc" };
        await _context.Categories.AddAsync(category);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.DeleteAsync(1, TestTenantId);

        // Assert
        Assert.True(result);
        var deletedCategory = await _context.Categories.FindAsync(1);
        Assert.Null(deletedCategory);
    }

    [Fact]
    public async Task DeleteAsync_ReturnsFalse_WhenNotExists()
    {
        // Act
        var result = await _repository.DeleteAsync(999, TestTenantId);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task DeleteAsync_ReturnsFalse_WhenExistsButDifferentTenant()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = OtherTenantId, Name = "To Delete", Description = "Delete Desc" };
        await _context.Categories.AddAsync(category);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.DeleteAsync(1, TestTenantId);

        // Assert
        Assert.False(result);
        // Verify the category still exists
        var existingCategory = await _context.Categories.FindAsync(1);
        Assert.NotNull(existingCategory);
    }

    #endregion
}

