using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Tests.Data;

[Trait("Category", "Integration")]
public class ItemRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly ItemRepository _repository;
    private const int TestTenantId = 1;
    private const int OtherTenantId = 2;
    private const int TestCollectionId = 1;
    private const int TestCategoryId = 1;

    public ItemRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _repository = new ItemRepository(_context);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    #region GetAllAsync Tests

    [Fact]
    public async Task GetAllAsync_ReturnsOnlyItemsForTenant()
    {
        // Arrange
        var items = new List<Item>
        {
            new() { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Item 1", CategoryId = TestCategoryId },
            new() { Id = 2, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Item 2", CategoryId = TestCategoryId },
            new() { Id = 3, TenantId = OtherTenantId, CollectionId = TestCollectionId, Name = "Item 3", CategoryId = TestCategoryId }
        };
        await _context.Items.AddRangeAsync(items);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetAllAsync(TestTenantId);

        // Assert
        Assert.Equal(2, result.Count());
        Assert.All(result, i => Assert.Equal(TestTenantId, i.TenantId));
    }

    [Fact]
    public async Task GetAllAsync_ReturnsEmptyList_WhenNoItemsExist()
    {
        // Act
        var result = await _repository.GetAllAsync(TestTenantId);

        // Assert
        Assert.Empty(result);
    }

    #endregion

    #region GetByCategoryIdsAsync Tests

    [Fact]
    public async Task GetByCategoryIdsAsync_ReturnsItemsInSpecifiedCategories()
    {
        // Arrange
        var items = new List<Item>
        {
            new() { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Item 1", CategoryId = 1 },
            new() { Id = 2, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Item 2", CategoryId = 2 },
            new() { Id = 3, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Item 3", CategoryId = 3 }
        };
        await _context.Items.AddRangeAsync(items);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByCategoryIdsAsync(new[] { 1, 2 }, TestTenantId);

        // Assert
        Assert.Equal(2, result.Count());
        Assert.All(result, i => Assert.True(i.CategoryId == 1 || i.CategoryId == 2));
    }

    [Fact]
    public async Task GetByCategoryIdsAsync_FiltersOutOtherTenants()
    {
        // Arrange
        var items = new List<Item>
        {
            new() { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Item 1", CategoryId = 1 },
            new() { Id = 2, TenantId = OtherTenantId, CollectionId = TestCollectionId, Name = "Item 2", CategoryId = 1 }
        };
        await _context.Items.AddRangeAsync(items);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByCategoryIdsAsync(new[] { 1 }, TestTenantId);

        // Assert
        Assert.Single(result);
        Assert.Equal(TestTenantId, result.First().TenantId);
    }

    [Fact]
    public async Task GetByCategoryIdsAsync_ReturnsEmpty_WhenNoCategoryMatch()
    {
        // Arrange
        var items = new List<Item>
        {
            new() { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Item 1", CategoryId = 1 }
        };
        await _context.Items.AddRangeAsync(items);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByCategoryIdsAsync(new[] { 999 }, TestTenantId);

        // Assert
        Assert.Empty(result);
    }

    #endregion

    #region GetByIdAsync Tests

    [Fact]
    public async Task GetByIdAsync_ReturnsItem_WhenExists()
    {
        // Arrange
        var item = new Item { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Test Item" };
        await _context.Items.AddAsync(item);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(1, TestTenantId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Test Item", result.Name);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenItemDoesNotExist()
    {
        // Act
        var result = await _repository.GetByIdAsync(999, TestTenantId);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenDifferentTenant()
    {
        // Arrange
        var item = new Item { Id = 1, TenantId = OtherTenantId, CollectionId = TestCollectionId, Name = "Test Item" };
        await _context.Items.AddAsync(item);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(1, TestTenantId);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region CreateAsync Tests

    [Fact]
    public async Task CreateAsync_AddsItemToDatabase()
    {
        // Arrange
        var item = new Item
        {
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Name = "New Item",
            Summary = "Summary",
            Description = "Description"
        };

        // Act
        var result = await _repository.CreateAsync(item);

        // Assert
        Assert.True(result.Id > 0);
        var savedItem = await _context.Items.FindAsync(result.Id);
        Assert.NotNull(savedItem);
        Assert.Equal("New Item", savedItem.Name);
    }

    [Fact]
    public async Task CreateAsync_ReturnsCreatedItem()
    {
        // Arrange
        var item = new Item
        {
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Name = "New Item"
        };

        // Act
        var result = await _repository.CreateAsync(item);

        // Assert
        Assert.Equal("New Item", result.Name);
        Assert.Equal(TestTenantId, result.TenantId);
    }

    #endregion

    #region UpdateAsync Tests

    [Fact]
    public async Task UpdateAsync_UpdatesExistingItem()
    {
        // Arrange
        var item = new Item
        {
            Id = 1,
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Name = "Original Name",
            Summary = "Original Summary"
        };
        await _context.Items.AddAsync(item);
        await _context.SaveChangesAsync();
        _context.Entry(item).State = EntityState.Detached;

        var updatedItem = new Item
        {
            Name = "Updated Name",
            Summary = "Updated Summary",
            Description = "Updated Description"
        };

        // Act
        var result = await _repository.UpdateAsync(1, updatedItem, TestTenantId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Updated Name", result.Name);
        Assert.Equal("Updated Summary", result.Summary);
    }

    [Fact]
    public async Task UpdateAsync_ReturnsNull_WhenItemDoesNotExist()
    {
        // Arrange
        var updatedItem = new Item { Name = "Updated Name" };

        // Act
        var result = await _repository.UpdateAsync(999, updatedItem, TestTenantId);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task UpdateAsync_ReturnsNull_WhenDifferentTenant()
    {
        // Arrange
        var item = new Item { Id = 1, TenantId = OtherTenantId, CollectionId = TestCollectionId, Name = "Test Item" };
        await _context.Items.AddAsync(item);
        await _context.SaveChangesAsync();
        _context.Entry(item).State = EntityState.Detached;

        var updatedItem = new Item { Name = "Updated Name" };

        // Act
        var result = await _repository.UpdateAsync(1, updatedItem, TestTenantId);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task UpdateAsync_UpdatesUserFlag()
    {
        // Arrange - Create item with None flag
        var item = new Item
        {
            Id = 1,
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Name = "Test Item",
            UserFlag = UserFlag.None
        };
        await _context.Items.AddAsync(item);
        await _context.SaveChangesAsync();
        _context.Entry(item).State = EntityState.Detached;

        // Act - Update to Want flag
        var updatedItem = new Item
        {
            Name = "Test Item",
            CollectionId = TestCollectionId,
            UserFlag = UserFlag.Want
        };
        var result = await _repository.UpdateAsync(1, updatedItem, TestTenantId);

        // Assert - Verify flag was updated
        Assert.NotNull(result);
        Assert.Equal(UserFlag.Want, result.UserFlag);

        // Also verify it's persisted in the database
        _context.Entry(result).State = EntityState.Detached;
        var savedItem = await _context.Items.FindAsync(1);
        Assert.Equal(UserFlag.Want, savedItem!.UserFlag);
    }

    [Theory]
    [InlineData(UserFlag.None, UserFlag.Have)]
    [InlineData(UserFlag.Have, UserFlag.Want)]
    [InlineData(UserFlag.Want, UserFlag.TradeOrSell)]
    [InlineData(UserFlag.TradeOrSell, UserFlag.None)]
    public async Task UpdateAsync_UpdatesUserFlag_AllTransitions(UserFlag initialFlag, UserFlag newFlag)
    {
        // Arrange
        var item = new Item
        {
            Id = 1,
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Name = "Test Item",
            UserFlag = initialFlag
        };
        await _context.Items.AddAsync(item);
        await _context.SaveChangesAsync();
        _context.Entry(item).State = EntityState.Detached;

        // Act
        var updatedItem = new Item
        {
            Name = "Test Item",
            CollectionId = TestCollectionId,
            UserFlag = newFlag
        };
        var result = await _repository.UpdateAsync(1, updatedItem, TestTenantId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(newFlag, result.UserFlag);
    }

    #endregion

    #region CreateAsync UserFlag Tests

    [Fact]
    public async Task CreateAsync_PersistsUserFlag()
    {
        // Arrange
        var item = new Item
        {
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Name = "Item with Flag",
            UserFlag = UserFlag.Want
        };

        // Act
        var result = await _repository.CreateAsync(item);

        // Assert
        Assert.Equal(UserFlag.Want, result.UserFlag);

        // Verify it's persisted
        var savedItem = await _context.Items.FindAsync(result.Id);
        Assert.Equal(UserFlag.Want, savedItem!.UserFlag);
    }

    [Theory]
    [InlineData(UserFlag.None)]
    [InlineData(UserFlag.Have)]
    [InlineData(UserFlag.Want)]
    [InlineData(UserFlag.TradeOrSell)]
    public async Task CreateAsync_PersistsAllUserFlagValues(UserFlag flag)
    {
        // Arrange
        var item = new Item
        {
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Name = $"Item with {flag}",
            UserFlag = flag
        };

        // Act
        var result = await _repository.CreateAsync(item);

        // Assert
        Assert.Equal(flag, result.UserFlag);
    }

    #endregion

    #region DeleteAsync Tests

    [Fact]
    public async Task DeleteAsync_ReturnsTrue_WhenItemExists()
    {
        // Arrange
        var item = new Item { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Test Item" };
        await _context.Items.AddAsync(item);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.DeleteAsync(1, TestTenantId);

        // Assert
        Assert.True(result);
        Assert.Null(await _context.Items.FindAsync(1));
    }

    [Fact]
    public async Task DeleteAsync_ReturnsFalse_WhenItemDoesNotExist()
    {
        // Act
        var result = await _repository.DeleteAsync(999, TestTenantId);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task DeleteAsync_ReturnsFalse_WhenDifferentTenant()
    {
        // Arrange
        var item = new Item { Id = 1, TenantId = OtherTenantId, CollectionId = TestCollectionId, Name = "Test Item" };
        await _context.Items.AddAsync(item);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.DeleteAsync(1, TestTenantId);

        // Assert
        Assert.False(result);
        Assert.NotNull(await _context.Items.FindAsync(1));
    }

    #endregion
}
