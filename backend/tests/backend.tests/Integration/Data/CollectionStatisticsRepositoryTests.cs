using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Tests.Integration;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Tests.Integration.Data;

[Trait("Category", "Integration")]
public class CollectionStatisticsRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly TestCollectionStatisticsRepository _repository;
    private const int TestCollectionId = 1;
    private const int TestWorkspaceId = 1;

    public CollectionStatisticsRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _repository = new TestCollectionStatisticsRepository(new TestDbContextFactory(options));
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    #region IncrementAsync Tests

    [Fact]
    public async Task IncrementAsync_CreatesNewStatistic_WhenNoneExists()
    {
        // Act
        await _repository.IncrementAsync(TestCollectionId, CollectionStatisticType.ItemCount);

        // Assert
        var stat = await _context.CollectionStatistics
            .FirstOrDefaultAsync(s => s.CollectionId == TestCollectionId && s.StatisticType == CollectionStatisticType.ItemCount);
        Assert.NotNull(stat);
        Assert.Equal(1, stat.Value);
    }

    [Fact]
    public async Task IncrementAsync_IncrementsExistingStatistic()
    {
        // Arrange
        _context.CollectionStatistics.Add(new CollectionStatistic
        {
            CollectionId = TestCollectionId,
            StatisticType = CollectionStatisticType.ItemCount,
            Value = 5,
        });
        await _context.SaveChangesAsync();

        // Act
        await _repository.IncrementAsync(TestCollectionId, CollectionStatisticType.ItemCount, 3);

        _context.ChangeTracker.Clear();

        // Assert
        var stat = await _context.CollectionStatistics
            .FirstOrDefaultAsync(s => s.CollectionId == TestCollectionId && s.StatisticType == CollectionStatisticType.ItemCount);
        Assert.NotNull(stat);
        Assert.Equal(8, stat.Value);
    }

    [Fact]
    public async Task IncrementAsync_IncrementsWithCustomAmount()
    {
        // Act
        await _repository.IncrementAsync(TestCollectionId, CollectionStatisticType.TotalImageSizeBytes, 1024);

        // Assert
        var stat = await _context.CollectionStatistics
            .FirstOrDefaultAsync(s => s.CollectionId == TestCollectionId && s.StatisticType == CollectionStatisticType.TotalImageSizeBytes);
        Assert.NotNull(stat);
        Assert.Equal(1024, stat.Value);
    }

    [Fact]
    public async Task IncrementAsync_HandlesDifferentTypes_Independently()
    {
        // Act
        await _repository.IncrementAsync(TestCollectionId, CollectionStatisticType.ItemCount, 5);
        await _repository.IncrementAsync(TestCollectionId, CollectionStatisticType.ImageCount, 3);

        // Assert
        var stats = await _context.CollectionStatistics
            .Where(s => s.CollectionId == TestCollectionId)
            .ToListAsync();
        Assert.Equal(2, stats.Count);
        Assert.Equal(5, stats.First(s => s.StatisticType == CollectionStatisticType.ItemCount).Value);
        Assert.Equal(3, stats.First(s => s.StatisticType == CollectionStatisticType.ImageCount).Value);
    }

    #endregion

    #region DecrementAsync Tests

    [Fact]
    public async Task DecrementAsync_DecrementsExistingStatistic()
    {
        // Arrange
        _context.CollectionStatistics.Add(new CollectionStatistic
        {
            CollectionId = TestCollectionId,
            StatisticType = CollectionStatisticType.ItemCount,
            Value = 10,
        });
        await _context.SaveChangesAsync();

        // Act
        await _repository.DecrementAsync(TestCollectionId, CollectionStatisticType.ItemCount, 3);

        _context.ChangeTracker.Clear();

        // Assert
        var stat = await _context.CollectionStatistics
            .FirstOrDefaultAsync(s => s.CollectionId == TestCollectionId && s.StatisticType == CollectionStatisticType.ItemCount);
        Assert.NotNull(stat);
        Assert.Equal(7, stat.Value);
    }

    [Fact]
    public async Task DecrementAsync_FloorsAtZero()
    {
        // Arrange
        _context.CollectionStatistics.Add(new CollectionStatistic
        {
            CollectionId = TestCollectionId,
            StatisticType = CollectionStatisticType.ItemCount,
            Value = 2,
        });
        await _context.SaveChangesAsync();

        // Act
        await _repository.DecrementAsync(TestCollectionId, CollectionStatisticType.ItemCount, 5);

        _context.ChangeTracker.Clear();

        // Assert
        var stat = await _context.CollectionStatistics
            .FirstOrDefaultAsync(s => s.CollectionId == TestCollectionId && s.StatisticType == CollectionStatisticType.ItemCount);
        Assert.NotNull(stat);
        Assert.Equal(0, stat.Value);
    }

    [Fact]
    public async Task DecrementAsync_DoesNothing_WhenNoStatisticExists()
    {
        // Act
        await _repository.DecrementAsync(TestCollectionId, CollectionStatisticType.ItemCount);

        // Assert
        var stats = await _context.CollectionStatistics.ToListAsync();
        Assert.Empty(stats);
    }

    #endregion

    #region GetAggregatesAsync Tests

    [Fact]
    public async Task GetAggregatesAsync_ReturnsAllStatistics()
    {
        // Arrange
        _context.CollectionStatistics.AddRange(
            new CollectionStatistic { CollectionId = TestCollectionId, StatisticType = CollectionStatisticType.ItemCount, Value = 10 },
            new CollectionStatistic { CollectionId = TestCollectionId, StatisticType = CollectionStatisticType.ImageCount, Value = 5 },
            new CollectionStatistic { CollectionId = TestCollectionId, StatisticType = CollectionStatisticType.TotalImageSizeBytes, Value = 2048 }
        );
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetAggregatesAsync(TestCollectionId);

        // Assert
        Assert.Equal(3, result.Count);
        Assert.Equal(10, result[CollectionStatisticType.ItemCount]);
        Assert.Equal(5, result[CollectionStatisticType.ImageCount]);
        Assert.Equal(2048, result[CollectionStatisticType.TotalImageSizeBytes]);
    }

    [Fact]
    public async Task GetAggregatesAsync_ReturnsEmptyDictionary_WhenNoStatistics()
    {
        // Act
        var result = await _repository.GetAggregatesAsync(TestCollectionId);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public async Task GetAggregatesAsync_OnlyReturnsStatsForSpecifiedCollection()
    {
        // Arrange
        _context.CollectionStatistics.AddRange(
            new CollectionStatistic { CollectionId = TestCollectionId, StatisticType = CollectionStatisticType.ItemCount, Value = 10 },
            new CollectionStatistic { CollectionId = 99, StatisticType = CollectionStatisticType.ItemCount, Value = 50 }
        );
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetAggregatesAsync(TestCollectionId);

        // Assert
        Assert.Single(result);
        Assert.Equal(10, result[CollectionStatisticType.ItemCount]);
    }

    #endregion

    #region IncrementItemViewAsync Tests

    [Fact]
    public async Task IncrementItemViewAsync_CreatesNewHighlight_WhenNoneExists()
    {
        // Arrange - need an item for the FK
        var item = new Item { Id = 1, CollectionId = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test Item" };
        _context.Items.Add(item);
        await _context.SaveChangesAsync();

        // Act
        await _repository.IncrementItemViewAsync(TestCollectionId, 1);

        // Assert
        var highlight = await _context.CollectionItemHighlights
            .FirstOrDefaultAsync(h => h.CollectionId == TestCollectionId && h.ItemId == 1);
        Assert.NotNull(highlight);
        Assert.Equal(1, highlight.ViewCount);
    }

    [Fact]
    public async Task IncrementItemViewAsync_IncrementsExistingHighlight()
    {
        // Arrange
        var item = new Item { Id = 1, CollectionId = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test Item" };
        _context.Items.Add(item);
        _context.CollectionItemHighlights.Add(new CollectionItemHighlight
        {
            CollectionId = TestCollectionId,
            ItemId = 1,
            ViewCount = 5,
        });
        await _context.SaveChangesAsync();

        // Act
        await _repository.IncrementItemViewAsync(TestCollectionId, 1);

        _context.ChangeTracker.Clear();

        // Assert
        var highlight = await _context.CollectionItemHighlights
            .FirstOrDefaultAsync(h => h.CollectionId == TestCollectionId && h.ItemId == 1);
        Assert.NotNull(highlight);
        Assert.Equal(6, highlight.ViewCount);
    }

    #endregion

    #region GetTopViewedItemsAsync Tests

    [Fact]
    public async Task GetTopViewedItemsAsync_ReturnsTopViewedItems_OrderedByViewCount()
    {
        // Arrange
        for (int i = 1; i <= 3; i++)
        {
            _context.Items.Add(new Item { Id = i, CollectionId = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = $"Item {i}" });
        }
        _context.CollectionItemHighlights.AddRange(
            new CollectionItemHighlight { CollectionId = TestCollectionId, ItemId = 1, ViewCount = 5 },
            new CollectionItemHighlight { CollectionId = TestCollectionId, ItemId = 2, ViewCount = 20 },
            new CollectionItemHighlight { CollectionId = TestCollectionId, ItemId = 3, ViewCount = 10 }
        );
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetTopViewedItemsAsync(TestCollectionId);

        // Assert
        Assert.Equal(3, result.Count);
        Assert.Equal(2, result[0].ItemId);
        Assert.Equal(20, result[0].ViewCount);
        Assert.Equal(3, result[1].ItemId);
        Assert.Equal(10, result[1].ViewCount);
        Assert.Equal(1, result[2].ItemId);
        Assert.Equal(5, result[2].ViewCount);
    }

    [Fact]
    public async Task GetTopViewedItemsAsync_RespectsCountLimit()
    {
        // Arrange
        for (int i = 1; i <= 5; i++)
        {
            _context.Items.Add(new Item { Id = i, CollectionId = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = $"Item {i}" });
            _context.CollectionItemHighlights.Add(new CollectionItemHighlight
            {
                CollectionId = TestCollectionId,
                ItemId = i,
                ViewCount = i * 10,
            });
        }
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetTopViewedItemsAsync(TestCollectionId, count: 2);

        // Assert
        Assert.Equal(2, result.Count);
        Assert.Equal(5, result[0].ItemId);
        Assert.Equal(4, result[1].ItemId);
    }

    [Fact]
    public async Task GetTopViewedItemsAsync_ReturnsEmptyList_WhenNoHighlights()
    {
        // Act
        var result = await _repository.GetTopViewedItemsAsync(TestCollectionId);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public async Task GetTopViewedItemsAsync_IncludesItemNavigation()
    {
        // Arrange
        _context.Items.Add(new Item { Id = 1, CollectionId = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "My Item" });
        _context.CollectionItemHighlights.Add(new CollectionItemHighlight
        {
            CollectionId = TestCollectionId,
            ItemId = 1,
            ViewCount = 10,
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetTopViewedItemsAsync(TestCollectionId);

        // Assert
        Assert.Single(result);
        Assert.NotNull(result[0].Item);
        Assert.Equal("My Item", result[0].Item!.Name);
    }

    #endregion

    #region GetRecentlyAddedItemsAsync Tests

    [Fact]
    public async Task GetRecentlyAddedItemsAsync_ReturnsItems_OrderedByCreatedAtDescending()
    {
        // Arrange
        var baseTime = DateTime.UtcNow;
        _context.Items.AddRange(
            new Item { Id = 1, CollectionId = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Old", CreatedAt = baseTime.AddDays(-3) },
            new Item { Id = 2, CollectionId = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "New", CreatedAt = baseTime },
            new Item { Id = 3, CollectionId = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Mid", CreatedAt = baseTime.AddDays(-1) }
        );
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetRecentlyAddedItemsAsync(TestCollectionId, TestWorkspaceId);

        // Assert
        Assert.Equal(3, result.Count);
        Assert.Equal("New", result[0].Name);
        Assert.Equal("Mid", result[1].Name);
        Assert.Equal("Old", result[2].Name);
    }

    [Fact]
    public async Task GetRecentlyAddedItemsAsync_RespectsCountLimit()
    {
        // Arrange
        var baseTime = DateTime.UtcNow;
        for (int i = 1; i <= 5; i++)
        {
            _context.Items.Add(new Item
            {
                Id = i,
                CollectionId = TestCollectionId,
                WorkspaceId = TestWorkspaceId,
                Name = $"Item {i}",
                CreatedAt = baseTime.AddDays(-i),
            });
        }
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetRecentlyAddedItemsAsync(TestCollectionId, TestWorkspaceId, count: 2);

        // Assert
        Assert.Equal(2, result.Count);
    }

    [Fact]
    public async Task GetRecentlyAddedItemsAsync_OnlyReturnsItemsForSpecifiedCollection()
    {
        // Arrange
        _context.Items.AddRange(
            new Item { Id = 1, CollectionId = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "In collection" },
            new Item { Id = 2, CollectionId = 99, WorkspaceId = TestWorkspaceId, Name = "Other collection" }
        );
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetRecentlyAddedItemsAsync(TestCollectionId, TestWorkspaceId);

        // Assert
        Assert.Single(result);
        Assert.Equal("In collection", result[0].Name);
    }

    [Fact]
    public async Task GetRecentlyAddedItemsAsync_ReturnsEmptyList_WhenNoItems()
    {
        // Act
        var result = await _repository.GetRecentlyAddedItemsAsync(TestCollectionId, TestWorkspaceId);

        // Assert
        Assert.Empty(result);
    }

    #endregion

    #region RemoveItemHighlightAsync Tests

    [Fact]
    public async Task RemoveItemHighlightAsync_RemovesExistingHighlight()
    {
        // Arrange
        var item = new Item { Id = 1, CollectionId = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test" };
        _context.Items.Add(item);
        _context.CollectionItemHighlights.Add(new CollectionItemHighlight
        {
            CollectionId = TestCollectionId,
            ItemId = 1,
            ViewCount = 10,
        });
        await _context.SaveChangesAsync();

        // Act
        await _repository.RemoveItemHighlightAsync(TestCollectionId, 1);

        // Assert
        var highlight = await _context.CollectionItemHighlights
            .FirstOrDefaultAsync(h => h.CollectionId == TestCollectionId && h.ItemId == 1);
        Assert.Null(highlight);
    }

    [Fact]
    public async Task RemoveItemHighlightAsync_DoesNothing_WhenHighlightDoesNotExist()
    {
        // Act (should not throw)
        await _repository.RemoveItemHighlightAsync(TestCollectionId, 999);

        // Assert
        var highlights = await _context.CollectionItemHighlights.ToListAsync();
        Assert.Empty(highlights);
    }

    #endregion

    #region DeleteCollectionStatsAsync Tests

    [Fact]
    public async Task DeleteCollectionStatsAsync_RemovesAllStatsAndHighlights()
    {
        // Arrange
        var item = new Item { Id = 1, CollectionId = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test" };
        _context.Items.Add(item);
        _context.CollectionStatistics.AddRange(
            new CollectionStatistic { CollectionId = TestCollectionId, StatisticType = CollectionStatisticType.ItemCount, Value = 10 },
            new CollectionStatistic { CollectionId = TestCollectionId, StatisticType = CollectionStatisticType.ImageCount, Value = 5 }
        );
        _context.CollectionItemHighlights.Add(new CollectionItemHighlight
        {
            CollectionId = TestCollectionId,
            ItemId = 1,
            ViewCount = 20,
        });
        await _context.SaveChangesAsync();

        // Act
        await _repository.DeleteCollectionStatsAsync(TestCollectionId);

        // Assert
        var stats = await _context.CollectionStatistics.Where(s => s.CollectionId == TestCollectionId).ToListAsync();
        var highlights = await _context.CollectionItemHighlights.Where(h => h.CollectionId == TestCollectionId).ToListAsync();
        Assert.Empty(stats);
        Assert.Empty(highlights);
    }

    [Fact]
    public async Task DeleteCollectionStatsAsync_DoesNotAffectOtherCollections()
    {
        // Arrange
        _context.CollectionStatistics.AddRange(
            new CollectionStatistic { CollectionId = TestCollectionId, StatisticType = CollectionStatisticType.ItemCount, Value = 10 },
            new CollectionStatistic { CollectionId = 99, StatisticType = CollectionStatisticType.ItemCount, Value = 50 }
        );
        await _context.SaveChangesAsync();

        // Act
        await _repository.DeleteCollectionStatsAsync(TestCollectionId);

        // Assert
        var remainingStats = await _context.CollectionStatistics.ToListAsync();
        Assert.Single(remainingStats);
        Assert.Equal(99, remainingStats[0].CollectionId);
    }

    #endregion
}
