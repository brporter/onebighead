using Moq;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Items;

namespace OneBigHead.Server.Tests.Unit.Services;

public class ItemViewRecorderTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Record_CountsOnlyScopedItemsUsingTheInjectedUtcDay(bool exists)
    {
        var items = new Mock<IItemRepository>();
        var workspaces = new Mock<IWorkspaceStatisticsRepository>();
        var collections = new Mock<ICollectionStatisticsRepository>();
        items.Setup(repository => repository.GetByIdAsync(20, 7)).ReturnsAsync(exists ? new Item { Id = 20, CollectionId = 3 } : null);

        await new ItemViewRecorder(items.Object, workspaces.Object, collections.Object, new Clock()).RecordAsync(7, 20);

        items.Verify(repository => repository.GetByIdAsync(20, 7), Times.Once);
        workspaces.Verify(repository => repository.IncrementAsync(7, StatisticType.DailyItemView, 1, new DateOnly(2025, 12, 31)),
            exists ? Times.Once() : Times.Never());
        collections.Verify(repository => repository.IncrementItemViewAsync(3, 20), exists ? Times.Once() : Times.Never());
        workspaces.VerifyNoOtherCalls();
        collections.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Record_ToleratesAnUnavailableItemStoreWithoutWritingStatistics()
    {
        var items = new Mock<IItemRepository>();
        var workspaces = new Mock<IWorkspaceStatisticsRepository>(MockBehavior.Strict);
        var collections = new Mock<ICollectionStatisticsRepository>(MockBehavior.Strict);
        items.Setup(repository => repository.GetByIdAsync(20, 7)).ThrowsAsync(new InvalidOperationException("Offline"));

        await new ItemViewRecorder(items.Object, workspaces.Object, collections.Object, new Clock()).RecordAsync(7, 20);

        workspaces.VerifyNoOtherCalls();
        collections.VerifyNoOtherCalls();
    }

    private sealed class Clock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => new(2026, 1, 1, 1, 30, 0, TimeSpan.FromHours(2));
    }
}
