using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Moq;
using OneBigHead.Server.Services.BulkUpdate;
using OneBigHead.Server.Telemetry;
using OneBigHead.Server.Tests.Hosting;

namespace OneBigHead.Server.Tests.Services;

[Collection(TelemetryConfigurationCollection.Name)]
public class BulkUpdateProcessorTests
{
    private readonly Mock<IBulkUpdateTargets> _targets = new();
    private readonly Mock<IBulkUpdateProperties> _properties = new();
    private readonly Mock<IBulkUpdateCollectionLocks> _collections = new();
    private readonly Mock<ILogger<BulkUpdateProcessor>> _logger = new();
    private readonly BulkUpdateJob _job = new()
    {
        WorkspaceId = 1, Target = new(BulkUpdateScope.Template, TemplateKey: Guid.NewGuid()),
        Diff = new([]), NewPropertyOrder = []
    };

    private BulkUpdateProcessor Processor => new(_targets.Object, _properties.Object, _collections.Object, _logger.Object);

    private void Items(params BulkUpdateItem[] items)
        => _targets.Setup(value => value.GetAsync(_job.Target, 1, It.IsAny<CancellationToken>())).ReturnsAsync(items);

    [Fact]
    public async Task LostAccess_StopsRemainingWritesAndReleasesCollections()
    {
        Items(new(1, 10), new(2, 20));
        _properties.Setup(value => value.ApplyAsync(_job, 1, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new UnauthorizedAccessException("Private access detail"));
        await Processor.ProcessAsync(_job, CancellationToken.None);
        Assert.Equal(BulkUpdateJobStatus.Failed, _job.Status);
        Assert.Equal(0, _job.ProcessedItems);
        Assert.DoesNotContain("Private access detail", _job.ErrorMessage);
        _properties.Verify(value => value.ApplyAsync(_job, 2, It.IsAny<CancellationToken>()), Times.Never);
        _collections.Verify(value => value.ReleaseCollectionLock(10, _job.JobId), Times.Once);
        _collections.Verify(value => value.ReleaseCollectionLock(20, _job.JobId), Times.Once);
    }

    [Fact]
    public async Task UpdatesAllTargets_AndMarksEveryAffectedCollectionBeforeWriting()
    {
        Items(new(1, 10), new(2, 20), new(3, 10));
        _properties.Setup(value => value.ApplyAsync(_job, It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(() =>
            {
                Assert.Equal(BulkUpdateJobStatus.Running, _job.Status);
                Assert.Equal(3, _job.TotalItems);
                _collections.Verify(value => value.RegisterCollectionLock(10, _job.JobId), Times.Once);
                _collections.Verify(value => value.RegisterCollectionLock(20, _job.JobId), Times.Once);
                return true;
            });
        await Processor.ProcessAsync(_job, CancellationToken.None);
        Assert.Equal(BulkUpdateJobStatus.Completed, _job.Status);
        Assert.Equal(3, _job.ProcessedItems);
        Assert.Equal(0, _job.FailedItems);
        Assert.NotNull(_job.CompletedAt);
        _collections.Verify(value => value.ReleaseCollectionLock(10, _job.JobId), Times.Once);
        _collections.Verify(value => value.ReleaseCollectionLock(20, _job.JobId), Times.Once);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MissingItemsAndWriteFailures_AreCountedAndDoNotStopRemainingItems(bool unrelatedCancellation)
    {
        Items(new(1, 10), new(2, 10), new(3, 10));
        _properties.Setup(value => value.ApplyAsync(_job, 1, It.IsAny<CancellationToken>())).ReturnsAsync(false);
        _properties.Setup(value => value.ApplyAsync(_job, 2, It.IsAny<CancellationToken>()))
            .ThrowsAsync(unrelatedCancellation ? new OperationCanceledException() : new InvalidOperationException("private database detail"));
        _properties.Setup(value => value.ApplyAsync(_job, 3, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        await Processor.ProcessAsync(_job, CancellationToken.None);
        Assert.Equal(BulkUpdateJobStatus.Completed, _job.Status);
        Assert.Equal(1, _job.ProcessedItems);
        Assert.Equal(2, _job.FailedItems);
        Assert.Null(_job.ErrorMessage);
        _logger.Verify(value => value.Log(LogLevel.Warning, It.IsAny<EventId>(), It.IsAny<It.IsAnyType>(),
            It.IsAny<Exception>(), It.IsAny<Func<It.IsAnyType, Exception?, string>>()), Times.Once);
    }

    [Fact]
    public async Task EmptySelection_CompletesWithoutLockingOrWriting()
    {
        Items();
        await Processor.ProcessAsync(_job, CancellationToken.None);
        Assert.Equal(BulkUpdateJobStatus.Completed, _job.Status);
        Assert.Equal(0, _job.TotalItems);
        _collections.VerifyNoOtherCalls();
        _properties.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task AlreadyCancelled_DoesNotReadOrWrite_AndReportsInterruption()
    {
        await Processor.ProcessAsync(_job, new CancellationToken(true));
        Assert.Equal(BulkUpdateJobStatus.Cancelled, _job.Status);
        Assert.Contains("interrupted", _job.ErrorMessage);
        Assert.NotNull(_job.CompletedAt);
        _targets.VerifyNoOtherCalls();
        _properties.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ShutdownDuringWrite_PreservesProgressAndReleasesCollections(bool throws)
    {
        using var cancellation = new CancellationTokenSource();
        Items(new(1, 10), new(2, 20));
        _properties.Setup(value => value.ApplyAsync(_job, 1, cancellation.Token)).ReturnsAsync(() =>
        {
            cancellation.Cancel();
            if (throws) throw new OperationCanceledException(cancellation.Token);
            return true;
        });
        await Processor.ProcessAsync(_job, cancellation.Token);
        Assert.Equal(BulkUpdateJobStatus.Cancelled, _job.Status);
        Assert.Equal(throws ? 0 : 1, _job.ProcessedItems);
        Assert.Equal(0, _job.FailedItems);
        Assert.Equal(2, _job.TotalItems);
        _properties.Verify(value => value.ApplyAsync(_job, 2, It.IsAny<CancellationToken>()), Times.Never);
        _collections.Verify(value => value.ReleaseCollectionLock(10, _job.JobId), Times.Once);
        _collections.Verify(value => value.ReleaseCollectionLock(20, _job.JobId), Times.Once);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SelectionFailure_IsReportedWithoutLeakingExceptionDetails(bool tracing)
    {
        Activity? recorded = null;
        var source = DiagnosticsConfig.AppActivitySource;
        using var listener = new ActivityListener
        {
            ShouldListenTo = candidate => tracing && ReferenceEquals(candidate, source),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity =>
            {
                if (Equals(activity.GetTagItem("job.id"), _job.JobId.ToString())) recorded = activity;
            }
        };
        ActivitySource.AddActivityListener(listener);
        _targets.Setup(value => value.GetAsync(_job.Target, 1, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException("private database detail"));
        await Processor.ProcessAsync(_job, CancellationToken.None);
        Assert.Equal(BulkUpdateJobStatus.Failed, _job.Status);
        Assert.DoesNotContain("private database detail", _job.ErrorMessage);
        Assert.NotNull(_job.CompletedAt);
        if (tracing)
        {
            Assert.NotNull(recorded);
            Assert.Equal(_job.JobId.ToString(), recorded.GetTagItem("job.id"));
            Assert.Equal(1, recorded.GetTagItem("job.workspaceId"));
            Assert.Contains(recorded.Events, value => value.Name == "exception");
            Assert.Equal(0, recorded.GetTagItem("job.processedItems"));
        }
        else Assert.Null(recorded);
        _properties.VerifyNoOtherCalls();
        _collections.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task FailureDuringCollectionRegistration_ReleasesPreviouslyRegisteredCollection()
    {
        Items(new(1, 10), new(2, 20));
        _collections.Setup(value => value.RegisterCollectionLock(20, _job.JobId)).Throws(new InvalidOperationException());
        await Processor.ProcessAsync(_job, CancellationToken.None);
        Assert.Equal(BulkUpdateJobStatus.Failed, _job.Status);
        _collections.Verify(value => value.ReleaseCollectionLock(10, _job.JobId), Times.Once);
        _collections.Verify(value => value.ReleaseCollectionLock(20, _job.JobId), Times.Never);
        _properties.VerifyNoOtherCalls();
    }
}
