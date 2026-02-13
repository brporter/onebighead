using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.BulkUpdate;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;

namespace OneBigHead.Server.Tests.Services;

[Trait("Category", "Unit")]
public class BulkUpdateWorkerTests
{
    private readonly BulkUpdateQueue _queue = new();
    private readonly Mock<IItemRepository> _mockItemRepo = new();
    private readonly Mock<IPropertyDiffService> _mockDiffService = new();
    private readonly Mock<ILogger<BulkUpdateWorker>> _mockLogger = new();

    private BulkUpdateWorker CreateWorker()
    {
        var services = new ServiceCollection();
        services.AddSingleton(_mockItemRepo.Object);
        services.AddSingleton(_mockDiffService.Object);
        var provider = services.BuildServiceProvider();

        var scopeFactory = provider.GetRequiredService<IServiceScopeFactory>();

        return new BulkUpdateWorker(_queue, scopeFactory, _mockLogger.Object);
    }

    [Fact]
    public async Task ProcessesJob_EndToEnd()
    {
        var templateKey = Guid.NewGuid();
        var items = new List<Item>
        {
            new() { Id = 1, WorkspaceId = 1, CollectionId = 10, Name = "Item 1", Properties = new List<ItemProperty> { new("Specs", "CPU", "i7") } },
            new() { Id = 2, WorkspaceId = 1, CollectionId = 10, Name = "Item 2", Properties = new List<ItemProperty> { new("Specs", "CPU", "i5") } },
        };

        _mockItemRepo.Setup(r => r.GetByTemplateKeyAsync(templateKey, 1))
            .ReturnsAsync(items);
        _mockItemRepo.Setup(r => r.UpdateAsync(It.IsAny<int>(), It.IsAny<Item>(), 1))
            .ReturnsAsync((int id, Item item, int _) => item);

        var updatedProps = new List<ItemProperty> { new("Hardware", "Processor", "i7") };
        _mockDiffService.Setup(d => d.ApplyDiff(It.IsAny<List<ItemProperty>>(), It.IsAny<PropertyDiff>(), It.IsAny<List<PropertyIdentifier>>()))
            .Returns(updatedProps);

        var job = new BulkUpdateJob
        {
            WorkspaceId = 1,
            Scope = BulkUpdateScope.Template,
            TemplateKey = templateKey,
            Diff = new PropertyDiff(new List<PropertyChange>()),
            NewPropertyOrder = new List<PropertyIdentifier>(),
        };

        _queue.Enqueue(job);

        var worker = CreateWorker();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var workerTask = worker.StartAsync(cts.Token);

        // Wait for job to complete
        while (job.Status != BulkUpdateJobStatus.Completed && !cts.IsCancellationRequested)
        {
            await Task.Delay(50, cts.Token);
        }

        await cts.CancelAsync();
        await worker.StopAsync(CancellationToken.None);

        Assert.Equal(BulkUpdateJobStatus.Completed, job.Status);
        Assert.Equal(2, job.TotalItems);
        Assert.Equal(2, job.ProcessedItems);
        Assert.Equal(0, job.FailedItems);
        _mockItemRepo.Verify(r => r.UpdateAsync(It.IsAny<int>(), It.IsAny<Item>(), 1), Times.Exactly(2));
    }

    [Fact]
    public async Task SkipsExcludedItem()
    {
        var templateKey = Guid.NewGuid();
        var items = new List<Item>
        {
            new() { Id = 1, WorkspaceId = 1, CollectionId = 10, Name = "Item 1", Properties = new() },
            new() { Id = 2, WorkspaceId = 1, CollectionId = 10, Name = "Item 2", Properties = new() },
            new() { Id = 3, WorkspaceId = 1, CollectionId = 10, Name = "Item 3", Properties = new() },
        };

        _mockItemRepo.Setup(r => r.GetByTemplateKeyAsync(templateKey, 1))
            .ReturnsAsync(items);
        _mockItemRepo.Setup(r => r.UpdateAsync(It.IsAny<int>(), It.IsAny<Item>(), 1))
            .ReturnsAsync((int id, Item item, int _) => item);
        _mockDiffService.Setup(d => d.ApplyDiff(It.IsAny<List<ItemProperty>>(), It.IsAny<PropertyDiff>(), It.IsAny<List<PropertyIdentifier>>()))
            .Returns(new List<ItemProperty>());

        var job = new BulkUpdateJob
        {
            WorkspaceId = 1,
            Scope = BulkUpdateScope.Template,
            TemplateKey = templateKey,
            ExcludeItemId = 2,
            Diff = new PropertyDiff(new List<PropertyChange>()),
            NewPropertyOrder = new List<PropertyIdentifier>(),
        };

        _queue.Enqueue(job);

        var worker = CreateWorker();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var workerTask = worker.StartAsync(cts.Token);

        while (job.Status != BulkUpdateJobStatus.Completed && !cts.IsCancellationRequested)
        {
            await Task.Delay(50, cts.Token);
        }

        await cts.CancelAsync();
        await worker.StopAsync(CancellationToken.None);

        Assert.Equal(2, job.TotalItems); // 3 items minus 1 excluded
        Assert.Equal(2, job.ProcessedItems);
        _mockItemRepo.Verify(r => r.UpdateAsync(2, It.IsAny<Item>(), 1), Times.Never);
    }

    [Fact]
    public async Task HandlesPerItemFailures_WithoutAbortingJob()
    {
        var templateKey = Guid.NewGuid();
        var items = new List<Item>
        {
            new() { Id = 1, WorkspaceId = 1, CollectionId = 10, Name = "Item 1", Properties = new() },
            new() { Id = 2, WorkspaceId = 1, CollectionId = 10, Name = "Item 2", Properties = new() },
            new() { Id = 3, WorkspaceId = 1, CollectionId = 10, Name = "Item 3", Properties = new() },
        };

        _mockItemRepo.Setup(r => r.GetByTemplateKeyAsync(templateKey, 1))
            .ReturnsAsync(items);
        _mockDiffService.Setup(d => d.ApplyDiff(It.IsAny<List<ItemProperty>>(), It.IsAny<PropertyDiff>(), It.IsAny<List<PropertyIdentifier>>()))
            .Returns(new List<ItemProperty>());

        // Item 2 fails on update
        _mockItemRepo.Setup(r => r.UpdateAsync(1, It.IsAny<Item>(), 1)).ReturnsAsync((int id, Item item, int _) => item);
        _mockItemRepo.Setup(r => r.UpdateAsync(2, It.IsAny<Item>(), 1)).ThrowsAsync(new Exception("DB error"));
        _mockItemRepo.Setup(r => r.UpdateAsync(3, It.IsAny<Item>(), 1)).ReturnsAsync((int id, Item item, int _) => item);

        var job = new BulkUpdateJob
        {
            WorkspaceId = 1,
            Scope = BulkUpdateScope.Template,
            TemplateKey = templateKey,
            Diff = new PropertyDiff(new List<PropertyChange>()),
            NewPropertyOrder = new List<PropertyIdentifier>(),
        };

        _queue.Enqueue(job);

        var worker = CreateWorker();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await worker.StartAsync(cts.Token);

        while (job.Status != BulkUpdateJobStatus.Completed && !cts.IsCancellationRequested)
        {
            await Task.Delay(50, cts.Token);
        }

        await cts.CancelAsync();
        await worker.StopAsync(CancellationToken.None);

        Assert.Equal(BulkUpdateJobStatus.Completed, job.Status);
        Assert.Equal(3, job.TotalItems);
        Assert.Equal(2, job.ProcessedItems);
        Assert.Equal(1, job.FailedItems);
    }

    [Fact]
    public async Task SetsCorrectStatusAndProgress()
    {
        var collectionId = 10;
        var items = new List<Item>
        {
            new() { Id = 1, WorkspaceId = 1, CollectionId = collectionId, Name = "Item 1", Properties = new() },
        };

        _mockItemRepo.Setup(r => r.GetByCollectionIdAsync(collectionId, 1))
            .ReturnsAsync(items);
        _mockItemRepo.Setup(r => r.UpdateAsync(It.IsAny<int>(), It.IsAny<Item>(), 1))
            .ReturnsAsync((int id, Item item, int _) => item);
        _mockDiffService.Setup(d => d.ApplyDiff(It.IsAny<List<ItemProperty>>(), It.IsAny<PropertyDiff>(), It.IsAny<List<PropertyIdentifier>>()))
            .Returns(new List<ItemProperty>());

        var job = new BulkUpdateJob
        {
            WorkspaceId = 1,
            Scope = BulkUpdateScope.Collection,
            CollectionId = collectionId,
            Diff = new PropertyDiff(new List<PropertyChange>()),
            NewPropertyOrder = new List<PropertyIdentifier>(),
        };

        Assert.Equal(BulkUpdateJobStatus.Queued, job.Status);

        _queue.Enqueue(job);

        var worker = CreateWorker();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await worker.StartAsync(cts.Token);

        while (job.Status != BulkUpdateJobStatus.Completed && !cts.IsCancellationRequested)
        {
            await Task.Delay(50, cts.Token);
        }

        await cts.CancelAsync();
        await worker.StopAsync(CancellationToken.None);

        Assert.Equal(BulkUpdateJobStatus.Completed, job.Status);
        Assert.NotNull(job.CompletedAt);
        Assert.Equal(1, job.TotalItems);
        Assert.Equal(1, job.ProcessedItems);
    }
}
