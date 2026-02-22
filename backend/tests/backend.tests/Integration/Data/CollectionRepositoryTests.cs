using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;
using Moq;

namespace OneBigHead.Server.Tests.Integration.Data;

[Trait("Category", "Integration")]
public class CollectionRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly CollectionRepository _repository;
    private const int TestWorkspaceId = 1;
    private const int OtherWorkspaceId = 2;

    public CollectionRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _repository = new CollectionRepository(_context, new Mock<IWorkspaceStatisticsRepository>().Object, new Mock<ICollectionStatisticsRepository>().Object);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    #region GetAllAsync Tests

    [Fact]
    public async Task GetAllAsync_ReturnsOnlyCollectionsForWorkspace()
    {
        // Arrange
        var collections = new List<Collection>
        {
            new() { Id = 1, WorkspaceId = TestWorkspaceId, Name = "Collection 1", Slug = "collection-1" },
            new() { Id = 2, WorkspaceId = TestWorkspaceId, Name = "Collection 2", Slug = "collection-2" },
            new() { Id = 3, WorkspaceId = OtherWorkspaceId, Name = "Collection 3", Slug = "collection-3" }
        };
        await _context.Collections.AddRangeAsync(collections);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetAllAsync(TestWorkspaceId);

        // Assert
        Assert.Equal(2, result.Count());
        Assert.All(result, c => Assert.Equal(TestWorkspaceId, c.WorkspaceId));
    }

    [Fact]
    public async Task GetAllAsync_ReturnsCollectionsOrderedByName()
    {
        // Arrange
        var collections = new List<Collection>
        {
            new() { Id = 1, WorkspaceId = TestWorkspaceId, Name = "Zebra", Slug = "zebra" },
            new() { Id = 2, WorkspaceId = TestWorkspaceId, Name = "Apple", Slug = "apple" },
            new() { Id = 3, WorkspaceId = TestWorkspaceId, Name = "Mango", Slug = "mango" }
        };
        await _context.Collections.AddRangeAsync(collections);
        await _context.SaveChangesAsync();

        // Act
        var result = (await _repository.GetAllAsync(TestWorkspaceId)).ToList();

        // Assert
        Assert.Equal("Apple", result[0].Name);
        Assert.Equal("Mango", result[1].Name);
        Assert.Equal("Zebra", result[2].Name);
    }

    [Fact]
    public async Task GetAllAsync_ReturnsEmptyList_WhenNoCollectionsExist()
    {
        // Act
        var result = await _repository.GetAllAsync(TestWorkspaceId);

        // Assert
        Assert.Empty(result);
    }

    #endregion

    #region GetByIdAsync Tests

    [Fact]
    public async Task GetByIdAsync_ReturnsCollection_WhenExists()
    {
        // Arrange
        var collection = new Collection { Id = 1, WorkspaceId = TestWorkspaceId, Name = "Test Collection", Slug = "test" };
        await _context.Collections.AddAsync(collection);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(1, TestWorkspaceId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Test Collection", result.Name);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenCollectionDoesNotExist()
    {
        // Act
        var result = await _repository.GetByIdAsync(999, TestWorkspaceId);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenDifferentWorkspace()
    {
        // Arrange
        var collection = new Collection { Id = 1, WorkspaceId = OtherWorkspaceId, Name = "Test Collection", Slug = "test" };
        await _context.Collections.AddAsync(collection);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(1, TestWorkspaceId);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region GetBySlugAsync Tests

    [Fact]
    public async Task GetBySlugAsync_ReturnsCollection_WhenExists()
    {
        // Arrange
        var collection = new Collection { Id = 1, WorkspaceId = TestWorkspaceId, Name = "Test Collection", Slug = "test-collection" };
        await _context.Collections.AddAsync(collection);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetBySlugAsync("test-collection", TestWorkspaceId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Test Collection", result.Name);
    }

    [Fact]
    public async Task GetBySlugAsync_ReturnsNull_WhenSlugDoesNotExist()
    {
        // Act
        var result = await _repository.GetBySlugAsync("nonexistent", TestWorkspaceId);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetBySlugAsync_ReturnsNull_WhenDifferentWorkspace()
    {
        // Arrange
        var collection = new Collection { Id = 1, WorkspaceId = OtherWorkspaceId, Name = "Test Collection", Slug = "test-collection" };
        await _context.Collections.AddAsync(collection);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetBySlugAsync("test-collection", TestWorkspaceId);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region CreateAsync Tests

    [Fact]
    public async Task CreateAsync_AddsCollectionToDatabase()
    {
        // Arrange
        var collection = new Collection
        {
            WorkspaceId = TestWorkspaceId,
            Name = "New Collection",
            Description = "Description",
            Slug = "new-collection"
        };

        // Act
        var result = await _repository.CreateAsync(collection);

        // Assert
        Assert.True(result.Id > 0);
        var savedCollection = await _context.Collections.FindAsync(result.Id);
        Assert.NotNull(savedCollection);
        Assert.Equal("New Collection", savedCollection.Name);
    }

    [Fact]
    public async Task CreateAsync_ReturnsCreatedCollection()
    {
        // Arrange
        var collection = new Collection
        {
            WorkspaceId = TestWorkspaceId,
            Name = "New Collection",
            Slug = "new-collection"
        };

        // Act
        var result = await _repository.CreateAsync(collection);

        // Assert
        Assert.Equal("New Collection", result.Name);
        Assert.Equal(TestWorkspaceId, result.WorkspaceId);
    }

    #endregion

    #region UpdateAsync Tests

    [Fact]
    public async Task UpdateAsync_UpdatesExistingCollection()
    {
        // Arrange
        var collection = new Collection
        {
            Id = 1,
            WorkspaceId = TestWorkspaceId,
            Name = "Original Name",
            Description = "Original Description",
            Slug = "original"
        };
        await _context.Collections.AddAsync(collection);
        await _context.SaveChangesAsync();
        _context.Entry(collection).State = EntityState.Detached;

        var updatedCollection = new Collection
        {
            Name = "Updated Name",
            Description = "Updated Description",
            Slug = "updated"
        };

        // Act
        var result = await _repository.UpdateAsync(1, updatedCollection, TestWorkspaceId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Updated Name", result.Name);
        Assert.Equal("Updated Description", result.Description);
        Assert.Equal("updated", result.Slug);
    }

    [Fact]
    public async Task UpdateAsync_ReturnsNull_WhenCollectionDoesNotExist()
    {
        // Arrange
        var updatedCollection = new Collection { Name = "Updated Name", Slug = "updated" };

        // Act
        var result = await _repository.UpdateAsync(999, updatedCollection, TestWorkspaceId);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task UpdateAsync_ReturnsNull_WhenDifferentWorkspace()
    {
        // Arrange
        var collection = new Collection { Id = 1, WorkspaceId = OtherWorkspaceId, Name = "Test Collection", Slug = "test" };
        await _context.Collections.AddAsync(collection);
        await _context.SaveChangesAsync();
        _context.Entry(collection).State = EntityState.Detached;

        var updatedCollection = new Collection { Name = "Updated Name", Slug = "updated" };

        // Act
        var result = await _repository.UpdateAsync(1, updatedCollection, TestWorkspaceId);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region DeleteAsync Tests

    [Fact]
    public async Task DeleteAsync_ReturnsTrue_WhenCollectionExists()
    {
        // Arrange
        var collection = new Collection { Id = 1, WorkspaceId = TestWorkspaceId, Name = "Test Collection", Slug = "test" };
        await _context.Collections.AddAsync(collection);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.DeleteAsync(1, TestWorkspaceId);

        // Assert
        Assert.True(result);
        Assert.Null(await _context.Collections.FindAsync(1));
    }

    [Fact]
    public async Task DeleteAsync_ReturnsFalse_WhenCollectionDoesNotExist()
    {
        // Act
        var result = await _repository.DeleteAsync(999, TestWorkspaceId);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task DeleteAsync_ReturnsFalse_WhenDifferentWorkspace()
    {
        // Arrange
        var collection = new Collection { Id = 1, WorkspaceId = OtherWorkspaceId, Name = "Test Collection", Slug = "test" };
        await _context.Collections.AddAsync(collection);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.DeleteAsync(1, TestWorkspaceId);

        // Assert
        Assert.False(result);
        Assert.NotNull(await _context.Collections.FindAsync(1));
    }

    #endregion

    #region GetCountAsync Tests

    [Fact]
    public async Task GetCountAsync_ReturnsCorrectCount()
    {
        // Arrange
        var collections = new List<Collection>
        {
            new() { Id = 1, WorkspaceId = TestWorkspaceId, Name = "Collection 1", Slug = "collection-1" },
            new() { Id = 2, WorkspaceId = TestWorkspaceId, Name = "Collection 2", Slug = "collection-2" },
            new() { Id = 3, WorkspaceId = OtherWorkspaceId, Name = "Collection 3", Slug = "collection-3" }
        };
        await _context.Collections.AddRangeAsync(collections);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetCountAsync(TestWorkspaceId);

        // Assert
        Assert.Equal(2, result);
    }

    [Fact]
    public async Task GetCountAsync_ReturnsZero_WhenNoCollections()
    {
        // Act
        var result = await _repository.GetCountAsync(TestWorkspaceId);

        // Assert
        Assert.Equal(0, result);
    }

    #endregion
}
