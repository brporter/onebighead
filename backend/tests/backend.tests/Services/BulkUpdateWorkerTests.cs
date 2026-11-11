using Microsoft.Extensions.Logging;
using Moq;
using OneBigHead.Server.Services.BulkUpdate;

namespace OneBigHead.Server.Tests.Services;

public class BulkUpdateWorkerTests
{
    [Fact]
    public async Task Worker_ContinuesAfterQueueAndProcessorFailures_AndStopsWhileWaiting()
    {
        var queue = new Mock<IBulkUpdateQueue>();
        var processor = new Mock<IBulkUpdateProcessor>();
        var logger = new Mock<ILogger<BulkUpdateWorker>>();
        var job = new BulkUpdateJob();
        var waiting = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var reads = 0;
        queue.Setup(value => value.DequeueAsync(It.IsAny<CancellationToken>())).Returns((CancellationToken token) =>
            new ValueTask<BulkUpdateJob>(ReadAsync(token)));
        async Task<BulkUpdateJob> ReadAsync(CancellationToken token)
        {
            reads++;
            if (reads == 1) throw new InvalidOperationException("Queue failure");
            if (reads <= 3) return job;
            waiting.SetResult();
            await Task.Delay(Timeout.Infinite, token);
            throw new InvalidOperationException("Unreachable");
        }
        processor.SetupSequence(value => value.ProcessAsync(job, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException("Not host shutdown"))
            .Returns(Task.CompletedTask);
        using var worker = new BulkUpdateWorker(queue.Object, processor.Object, logger.Object);
        await worker.StartAsync(CancellationToken.None);
        await waiting.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await worker.StopAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(worker.ExecuteTask!.IsCompletedSuccessfully);
        processor.Verify(value => value.ProcessAsync(job, It.IsAny<CancellationToken>()), Times.Exactly(2));
        logger.Verify(value => value.Log(LogLevel.Error, It.IsAny<EventId>(), It.IsAny<It.IsAnyType>(),
            It.IsAny<Exception>(), It.IsAny<Func<It.IsAnyType, Exception?, string>>()), Times.Exactly(2));
    }

    [Fact]
    public async Task Worker_StopsAfterProcessorHandlesShutdown_WithoutReadingAnotherJob()
    {
        var queue = new Mock<IBulkUpdateQueue>();
        var processor = new Mock<IBulkUpdateProcessor>();
        var processing = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var job = new BulkUpdateJob();
        queue.Setup(value => value.DequeueAsync(It.IsAny<CancellationToken>())).ReturnsAsync(job);
        processor.Setup(value => value.ProcessAsync(job, It.IsAny<CancellationToken>()))
            .Returns(async (BulkUpdateJob _, CancellationToken token) =>
            {
                processing.SetResult();
                try { await Task.Delay(Timeout.Infinite, token); }
                catch (OperationCanceledException) { }
            });
        using var worker = new BulkUpdateWorker(queue.Object, processor.Object, Mock.Of<ILogger<BulkUpdateWorker>>());
        await worker.StartAsync(CancellationToken.None);
        await processing.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await worker.StopAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(worker.ExecuteTask!.IsCompletedSuccessfully);
        queue.Verify(value => value.DequeueAsync(It.IsAny<CancellationToken>()), Times.Once);
    }
}
