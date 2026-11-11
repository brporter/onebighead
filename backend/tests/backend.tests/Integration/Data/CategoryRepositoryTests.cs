using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Tests.Integration.Data;

[Trait("Category", "Integration")]
public class CategoryRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly CategoryRepository _repository;
    private const int TestWorkspaceId = 1;
    private const int OtherWorkspaceId = 2;
    private const int TestCollectionId = 1;
    private const int OtherCollectionId = 2;

    public CategoryRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _repository = new CategoryRepository(new TestDbContextFactory(options));
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    #region GetAllAsync Tests

    [Fact]
    public async Task GetAllAsync_ReturnsOnlyCategoriesForWorkspace()
    {
        // Arrange
        var categories = new List<Category>
        {
            new() { Id = 1, WorkspaceId = TestWorkspaceId, Name = "Category 1", Description = "Desc 1" },
            new() { Id = 2, WorkspaceId = TestWorkspaceId, Name = "Category 2", Description = "Desc 2" },
            new() { Id = 3, WorkspaceId = OtherWorkspaceId, Name = "Category 3", Description = "Desc 3" }
        };
        await _context.Categories.AddRangeAsync(categories);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetAllAsync(TestWorkspaceId);

        // Assert
        Assert.Equal(2, result.Count());
        Assert.All(result, c => Assert.Equal(TestWorkspaceId, c.WorkspaceId));
    }

    [Fact]
    public async Task GetAllAsync_ReturnsEmptyList_WhenNoCategories()
    {
        // Act
        var result = await _repository.GetAllAsync(TestWorkspaceId);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public async Task GetAllAsync_ReturnsCategoriesOrderedBySortOrderThenName()
    {
        // Arrange
        var categories = new List<Category>
        {
            new() { WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Bravo", SortOrder = 1 },
            new() { WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Alpha", SortOrder = 0 },
            new() { WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Charlie", SortOrder = 1 },
        };
        await _context.Categories.AddRangeAsync(categories);
        await _context.SaveChangesAsync();

        // Act
        var result = (await _repository.GetAllAsync(TestWorkspaceId)).ToList();

        // Assert
        Assert.Equal("Alpha", result[0].Name);
        Assert.Equal("Bravo", result[1].Name);
        Assert.Equal("Charlie", result[2].Name);
    }

    #endregion

    #region GetByCollectionAsync Tests

    [Fact]
    public async Task GetByCollectionAsync_ReturnsOnlyCategoriesForCollection()
    {
        // Arrange
        var categories = new List<Category>
        {
            new() { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Category 1", Description = "Desc 1" },
            new() { Id = 2, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Category 2", Description = "Desc 2" },
            new() { Id = 3, WorkspaceId = TestWorkspaceId, CollectionId = OtherCollectionId, Name = "Category 3", Description = "Desc 3" }
        };
        await _context.Categories.AddRangeAsync(categories);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByCollectionAsync(TestCollectionId, TestWorkspaceId);

        // Assert
        Assert.Equal(2, result.Count());
        Assert.All(result, c => Assert.Equal(TestCollectionId, c.CollectionId));
    }

    [Fact]
    public async Task GetByCollectionAsync_FiltersOutOtherWorkspaces()
    {
        // Arrange
        var categories = new List<Category>
        {
            new() { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Category 1", Description = "Desc 1" },
            new() { Id = 2, WorkspaceId = OtherWorkspaceId, CollectionId = TestCollectionId, Name = "Category 2", Description = "Desc 2" }
        };
        await _context.Categories.AddRangeAsync(categories);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByCollectionAsync(TestCollectionId, TestWorkspaceId);

        // Assert
        Assert.Single(result);
        Assert.Equal(TestWorkspaceId, result.First().WorkspaceId);
    }

    [Fact]
    public async Task GetByCollectionAsync_ReturnsEmptyList_WhenNoCategories()
    {
        // Act
        var result = await _repository.GetByCollectionAsync(TestCollectionId, TestWorkspaceId);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public async Task GetByCollectionAsync_ReturnsCategoriesOrderedBySortOrderThenName()
    {
        // Arrange
        var categories = new List<Category>
        {
            new() { WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Bravo", SortOrder = 1 },
            new() { WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Alpha", SortOrder = 0 },
            new() { WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Charlie", SortOrder = 1 },
        };
        await _context.Categories.AddRangeAsync(categories);
        await _context.SaveChangesAsync();

        // Act
        var result = (await _repository.GetByCollectionAsync(TestCollectionId, TestWorkspaceId)).ToList();

        // Assert
        Assert.Equal("Alpha", result[0].Name);
        Assert.Equal("Bravo", result[1].Name);
        Assert.Equal("Charlie", result[2].Name);
    }

    #endregion

    #region GetByIdAsync Tests

    [Fact]
    public async Task GetByIdAsync_ReturnsCategory_WhenExistsForWorkspace()
    {
        // Arrange
        var category = new Category { Id = 1, WorkspaceId = TestWorkspaceId, Name = "Test Category", Description = "Test Desc" };
        await _context.Categories.AddAsync(category);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(1, TestWorkspaceId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Test Category", result.Name);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenNotExists()
    {
        // Act
        var result = await _repository.GetByIdAsync(999, TestWorkspaceId);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenExistsButDifferentWorkspace()
    {
        // Arrange
        var category = new Category { Id = 1, WorkspaceId = OtherWorkspaceId, Name = "Test Category", Description = "Test Desc" };
        await _context.Categories.AddAsync(category);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(1, TestWorkspaceId);

        // Assert
        Assert.Null(result);
    }

    #endregion

}
