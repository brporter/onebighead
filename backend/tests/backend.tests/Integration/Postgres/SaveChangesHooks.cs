using Microsoft.EntityFrameworkCore.Diagnostics;

namespace OneBigHead.Server.Tests.Integration.Postgres;

internal sealed class SynchronizedSaves : SaveChangesInterceptor
{
    private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _arrived;
    public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        if (Interlocked.Increment(ref _arrived) == 2) _ready.SetResult();
        await _ready.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
        return result;
    }
}

internal sealed class BeforeMembershipSave(Func<Task> change) : SaveChangesInterceptor
{
    public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        await change();
        return result;
    }
}
