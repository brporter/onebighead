using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Tests.Integration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;

namespace OneBigHead.Server.Tests.Integration.Data;

[Trait("Category", "Integration")]
public class ItemRepositoryImageStatsTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly ItemRepository _repository;
    private readonly TestCollectionStatisticsRepository _collectionStatsRepo;
    private const int TestWorkspaceId = 1;
    private const int TestCollectionId = 10;

    public ItemRepositoryImageStatsTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _collectionStatsRepo = new TestCollectionStatisticsRepository(_context);
        _repository = new ItemRepository(
            _context,
            new Mock<IWorkspaceStatisticsRepository>().Object,
            _collectionStatsRepo,
            new Mock<ILogger<ItemRepository>>().Object);

        // Seed a collection so FK is valid
        _context.Collections.Add(new Collection
        {
            Id = TestCollectionId,
            WorkspaceId = TestWorkspaceId,
            Name = "Test Collection",
            Slug = "test-collection"
        });
        _context.SaveChanges();
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    private Guid SeedStoredImage(int sizeBytes)
    {
        var id = Guid.NewGuid();
        _context.StoredImages.Add(new StoredImage
        {
            Id = id,
            WorkspaceId = TestWorkspaceId,
            FileName = "test.jpg",
            ContentType = "image/jpeg",
            Data = new byte[sizeBytes],
            CreatedAt = DateTime.UtcNow,
        });
        _context.SaveChanges();
        return id;
    }

    #region CreateAsync Image Stats

    [Fact]
    public async Task CreateAsync_IncrementsImageCount_WhenItemHasImages()
    {
        // Arrange
        var imageId = SeedStoredImage(1024);
        var item = new Item
        {
            WorkspaceId = TestWorkspaceId,
            CollectionId = TestCollectionId,
            Name = "Item with image",
            Images = [new ItemImage($"/api/images/{imageId}", "alt")],
        };

        // Act
        await _repository.CreateAsync(item);

        // Assert
        var aggregates = await _collectionStatsRepo.GetAggregatesAsync(TestCollectionId);
        Assert.Equal(1, aggregates[CollectionStatisticType.ImageCount]);
        Assert.Equal(1024, aggregates[CollectionStatisticType.TotalImageSizeBytes]);
    }

    [Fact]
    public async Task CreateAsync_DoesNotIncrementImageCount_WhenItemHasNoImages()
    {
        // Arrange
        var item = new Item
        {
            WorkspaceId = TestWorkspaceId,
            CollectionId = TestCollectionId,
            Name = "Item without image",
            Images = [],
        };

        // Act
        await _repository.CreateAsync(item);

        // Assert
        var aggregates = await _collectionStatsRepo.GetAggregatesAsync(TestCollectionId);
        Assert.False(aggregates.ContainsKey(CollectionStatisticType.ImageCount));
    }

    [Fact]
    public async Task CreateAsync_IncrementsImageCount_ForMultipleImages()
    {
        // Arrange
        var imageId1 = SeedStoredImage(500);
        var imageId2 = SeedStoredImage(300);
        var item = new Item
        {
            WorkspaceId = TestWorkspaceId,
            CollectionId = TestCollectionId,
            Name = "Item with two images",
            Images =
            [
                new ItemImage($"/api/images/{imageId1}", "alt1"),
                new ItemImage($"/api/images/{imageId2}", "alt2"),
            ],
        };

        // Act
        await _repository.CreateAsync(item);

        // Assert
        var aggregates = await _collectionStatsRepo.GetAggregatesAsync(TestCollectionId);
        Assert.Equal(2, aggregates[CollectionStatisticType.ImageCount]);
        Assert.Equal(800, aggregates[CollectionStatisticType.TotalImageSizeBytes]);
    }

    #endregion

    #region UpdateAsync Image Stats

    [Fact]
    public async Task UpdateAsync_IncrementsImageCount_WhenImageAdded()
    {
        // Arrange — create item with no images
        var item = new Item
        {
            WorkspaceId = TestWorkspaceId,
            CollectionId = TestCollectionId,
            Name = "Item",
            Images = [],
        };
        _context.Items.Add(item);
        await _context.SaveChangesAsync();
        _context.Entry(item).State = EntityState.Detached;

        var imageId = SeedStoredImage(2048);
        var updatedItem = new Item
        {
            WorkspaceId = TestWorkspaceId,
            CollectionId = TestCollectionId,
            Name = "Item",
            Images = [new ItemImage($"/api/images/{imageId}", "new image")],
        };

        // Act
        await _repository.UpdateAsync(item.Id!.Value, updatedItem, TestWorkspaceId);

        // Assert
        var aggregates = await _collectionStatsRepo.GetAggregatesAsync(TestCollectionId);
        Assert.Equal(1, aggregates[CollectionStatisticType.ImageCount]);
        Assert.Equal(2048, aggregates[CollectionStatisticType.TotalImageSizeBytes]);
    }

    [Fact]
    public async Task UpdateAsync_DecrementsImageCount_WhenImageRemoved()
    {
        // Arrange — create item with one image
        var imageId = SeedStoredImage(1024);
        var item = new Item
        {
            WorkspaceId = TestWorkspaceId,
            CollectionId = TestCollectionId,
            Name = "Item",
            Images = [new ItemImage($"/api/images/{imageId}", "old image")],
        };
        _context.Items.Add(item);
        await _context.SaveChangesAsync();

        // Pre-seed collection stats for the existing image
        await _collectionStatsRepo.IncrementAsync(TestCollectionId, CollectionStatisticType.ImageCount);
        await _collectionStatsRepo.IncrementAsync(TestCollectionId, CollectionStatisticType.TotalImageSizeBytes, 1024);

        _context.Entry(item).State = EntityState.Detached;

        var updatedItem = new Item
        {
            WorkspaceId = TestWorkspaceId,
            CollectionId = TestCollectionId,
            Name = "Item",
            Images = [],
        };

        // Act
        await _repository.UpdateAsync(item.Id!.Value, updatedItem, TestWorkspaceId);

        // Assert
        var aggregates = await _collectionStatsRepo.GetAggregatesAsync(TestCollectionId);
        Assert.Equal(0, aggregates[CollectionStatisticType.ImageCount]);
        Assert.Equal(0, aggregates[CollectionStatisticType.TotalImageSizeBytes]);
    }

    [Fact]
    public async Task UpdateAsync_NoChange_WhenSameImages()
    {
        // Arrange — create item with one image
        var imageId = SeedStoredImage(512);
        var imageUrl = $"/api/images/{imageId}";
        var item = new Item
        {
            WorkspaceId = TestWorkspaceId,
            CollectionId = TestCollectionId,
            Name = "Item",
            Images = [new ItemImage(imageUrl, "image")],
        };
        _context.Items.Add(item);
        await _context.SaveChangesAsync();
        _context.Entry(item).State = EntityState.Detached;

        var updatedItem = new Item
        {
            WorkspaceId = TestWorkspaceId,
            CollectionId = TestCollectionId,
            Name = "Item renamed",
            Images = [new ItemImage(imageUrl, "image")],
        };

        // Act
        await _repository.UpdateAsync(item.Id!.Value, updatedItem, TestWorkspaceId);

        // Assert — no image stat changes
        var aggregates = await _collectionStatsRepo.GetAggregatesAsync(TestCollectionId);
        Assert.Empty(aggregates);
    }

    #endregion

    #region DeleteAsync Image Stats

    [Fact]
    public async Task DeleteAsync_DecrementsImageCount_WhenItemHasImages()
    {
        // Arrange
        var imageId = SeedStoredImage(4096);
        var item = new Item
        {
            WorkspaceId = TestWorkspaceId,
            CollectionId = TestCollectionId,
            Name = "Item with image",
            Images = [new ItemImage($"/api/images/{imageId}", "alt")],
        };
        _context.Items.Add(item);
        await _context.SaveChangesAsync();

        // Pre-seed collection stats
        await _collectionStatsRepo.IncrementAsync(TestCollectionId, CollectionStatisticType.ImageCount);
        await _collectionStatsRepo.IncrementAsync(TestCollectionId, CollectionStatisticType.TotalImageSizeBytes, 4096);

        // Act
        await _repository.DeleteAsync(item.Id!.Value, TestWorkspaceId);

        // Assert
        var aggregates = await _collectionStatsRepo.GetAggregatesAsync(TestCollectionId);
        Assert.Equal(0, aggregates[CollectionStatisticType.ImageCount]);
        Assert.Equal(0, aggregates[CollectionStatisticType.TotalImageSizeBytes]);
    }

    [Fact]
    public async Task DeleteAsync_DoesNotDecrementImageCount_WhenItemHasNoImages()
    {
        // Arrange
        var item = new Item
        {
            WorkspaceId = TestWorkspaceId,
            CollectionId = TestCollectionId,
            Name = "Item without image",
            Images = [],
        };
        _context.Items.Add(item);
        await _context.SaveChangesAsync();

        // Act
        await _repository.DeleteAsync(item.Id!.Value, TestWorkspaceId);

        // Assert
        var aggregates = await _collectionStatsRepo.GetAggregatesAsync(TestCollectionId);
        Assert.Empty(aggregates);
    }

    #endregion
}
