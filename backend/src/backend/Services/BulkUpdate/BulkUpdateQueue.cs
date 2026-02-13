using System.Collections.Concurrent;
using System.Threading.Channels;

namespace OneBigHead.Server.Services.BulkUpdate;

public class BulkUpdateQueue : IBulkUpdateQueue
{
    private readonly Channel<BulkUpdateJob> _channel = Channel.CreateUnbounded<BulkUpdateJob>(
        new UnboundedChannelOptions { SingleReader = true });

    private readonly ConcurrentDictionary<Guid, BulkUpdateJob> _jobs = new();
    private readonly ConcurrentDictionary<int, Guid> _activeCollectionIds = new();

    public void Enqueue(BulkUpdateJob job)
    {
        _jobs[job.JobId] = job;
        _channel.Writer.TryWrite(job);
    }

    public ValueTask<BulkUpdateJob> DequeueAsync(CancellationToken cancellationToken)
    {
        return _channel.Reader.ReadAsync(cancellationToken);
    }

    public BulkUpdateJob? GetJob(Guid jobId, int workspaceId)
    {
        CleanupStaleJobs();

        if (_jobs.TryGetValue(jobId, out var job) && job.WorkspaceId == workspaceId)
        {
            return job;
        }

        return null;
    }

    public BulkUpdateJob? GetActiveJobForCollection(int collectionId, int workspaceId)
    {
        if (_activeCollectionIds.TryGetValue(collectionId, out var jobId) &&
            _jobs.TryGetValue(jobId, out var job) &&
            job.WorkspaceId == workspaceId &&
            job.Status is BulkUpdateJobStatus.Queued or BulkUpdateJobStatus.Running)
        {
            return job;
        }

        return null;
    }

    public void RegisterCollectionLock(int collectionId, Guid jobId)
    {
        _activeCollectionIds[collectionId] = jobId;
    }

    public void ReleaseCollectionLock(int collectionId)
    {
        _activeCollectionIds.TryRemove(collectionId, out _);
    }

    private void CleanupStaleJobs()
    {
        var cutoff = DateTime.UtcNow.AddHours(-1);
        var staleJobIds = _jobs
            .Where(kvp => kvp.Value.CompletedAt.HasValue && kvp.Value.CompletedAt.Value < cutoff)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var id in staleJobIds)
        {
            _jobs.TryRemove(id, out _);
        }
    }
}
