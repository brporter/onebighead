using OneBigHead.Server.Services.BulkUpdate;

namespace OneBigHead.Server.Tests.Services;

[Trait("Category", "Unit")]
public class BulkUpdateQueueTests
{
    private readonly BulkUpdateQueue _queue = new();

    [Fact]
    public async Task Enqueue_Dequeue_ReturnsJobInOrder()
    {
        var job1 = CreateJob(1);
        var job2 = CreateJob(1);

        _queue.Enqueue(job1);
        _queue.Enqueue(job2);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        var dequeued1 = await _queue.DequeueAsync(cts.Token);
        var dequeued2 = await _queue.DequeueAsync(cts.Token);

        Assert.Equal(job1.JobId, dequeued1.JobId);
        Assert.Equal(job2.JobId, dequeued2.JobId);
    }

    [Fact]
    public void GetJob_WithMatchingWorkspace_ReturnsJob()
    {
        var job = CreateJob(1);
        _queue.Enqueue(job);

        var result = _queue.GetJob(job.JobId, 1);

        Assert.NotNull(result);
        Assert.Equal(job.JobId, result.JobId);
    }

    [Fact]
    public void GetJob_WithDifferentWorkspace_ReturnsNull()
    {
        var job = CreateJob(1);
        _queue.Enqueue(job);

        var result = _queue.GetJob(job.JobId, 2);

        Assert.Null(result);
    }

    [Fact]
    public void GetJob_WithNonExistentId_ReturnsNull()
    {
        var result = _queue.GetJob(Guid.NewGuid(), 1);
        Assert.Null(result);
    }

    [Fact]
    public void GetActiveJobForCollection_WhenLocked_ReturnsJob()
    {
        var job = CreateJob(1);
        job.Status = BulkUpdateJobStatus.Running;
        _queue.Enqueue(job);
        _queue.RegisterCollectionLock(10, job.JobId);

        var result = _queue.GetActiveJobForCollection(10, 1);

        Assert.NotNull(result);
        Assert.Equal(job.JobId, result.JobId);
    }

    [Fact]
    public void GetActiveJobForCollection_WhenNotLocked_ReturnsNull()
    {
        var result = _queue.GetActiveJobForCollection(10, 1);
        Assert.Null(result);
    }

    [Fact]
    public void GetActiveJobForCollection_AfterRelease_ReturnsNull()
    {
        var job = CreateJob(1);
        job.Status = BulkUpdateJobStatus.Running;
        _queue.Enqueue(job);
        _queue.RegisterCollectionLock(10, job.JobId);
        _queue.ReleaseCollectionLock(10);

        var result = _queue.GetActiveJobForCollection(10, 1);
        Assert.Null(result);
    }

    [Fact]
    public void GetActiveJobForCollection_WhenCompleted_ReturnsNull()
    {
        var job = CreateJob(1);
        job.Status = BulkUpdateJobStatus.Completed;
        _queue.Enqueue(job);
        _queue.RegisterCollectionLock(10, job.JobId);

        var result = _queue.GetActiveJobForCollection(10, 1);
        Assert.Null(result);
    }

    [Fact]
    public void GetActiveJobForCollection_WrongWorkspace_ReturnsNull()
    {
        var job = CreateJob(1);
        job.Status = BulkUpdateJobStatus.Running;
        _queue.Enqueue(job);
        _queue.RegisterCollectionLock(10, job.JobId);

        var result = _queue.GetActiveJobForCollection(10, 2);
        Assert.Null(result);
    }

    [Fact]
    public void GetJob_CleansUpStaleJobs()
    {
        var staleJob = CreateJob(1);
        staleJob.Status = BulkUpdateJobStatus.Completed;
        staleJob.CompletedAt = DateTime.UtcNow.AddHours(-2);
        _queue.Enqueue(staleJob);

        // Query triggers cleanup
        var result = _queue.GetJob(staleJob.JobId, 1);
        Assert.Null(result);
    }

    private static BulkUpdateJob CreateJob(int workspaceId) => new()
    {
        WorkspaceId = workspaceId,
        Scope = BulkUpdateScope.Template,
        TemplateKey = Guid.NewGuid(),
        Diff = new PropertyDiff(new List<PropertyChange>()),
        NewPropertyOrder = new List<PropertyIdentifier>(),
    };
}
