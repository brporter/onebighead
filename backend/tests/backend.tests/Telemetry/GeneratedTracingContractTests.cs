using System.Diagnostics;
using System.Reflection;
using OneBigHead.Server.Services;
using OneBigHead.Server.Services.Images;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Tests.Telemetry;

[Trait("Category", "Unit")]
public class GeneratedTracingContractTests
{
    public static IEnumerable<object[]> Contracts()
    {
        foreach (var contract in typeof(GenerateTracingProxyAttribute).Assembly.GetTypes().Where(type => type.IsInterface && type.IsDefined(typeof(GenerateTracingProxyAttribute))))
        foreach (var method in TracingContractHarness.Methods(contract))
        foreach (var enabled in new[] { false, true })
        foreach (var fail in new[] { false, true })
            yield return [contract.FullName!, TracingContractHarness.Signature(method), enabled, fail];
    }

    [Theory]
    [MemberData(nameof(Contracts))]
    public Task EveryDecoratedMethod_PreservesItsServiceContract(string name, string signature, bool enabled, bool fail)
    {
        var contract = typeof(GenerateTracingProxyAttribute).Assembly.GetType(name)!;
        var method = TracingContractHarness.Methods(contract).Single(method => TracingContractHarness.Signature(method) == signature);
        return TracingContractHarness.Verify(contract, method, enabled, fail);
    }

    [Theory]
    [InlineData("success")]
    [InlineData("failure")]
    [InlineData("cancel")]
    public async Task PendingOperation_EndsItsSpanOnlyWhenTheInnerTaskFinishes(string outcome)
    {
        using var parent = new Activity("caller").Start();
        using var source = new ActivitySource($"TracingLifetime.{Guid.NewGuid()}");
        var stopped = new List<Activity>();
        using var listener = TracingContractHarness.Listen(source, true, stopped);
        var pending = new TaskCompletionSource<RetrievedImage?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var inner = DispatchProxy.Create<IImageReader, RecordingService>();
        Activity? inside = null;
        ((RecordingService)inner).Handle = (_, _) => { inside = Activity.Current; return pending.Task; };
        var proxy = new TracingProxy_IImageReader(inner, source);
        var operation = proxy.ReadAsync(Guid.NewGuid(), null, null, CancellationToken.None);
        Assert.False(operation.IsCompleted);
        Assert.Empty(stopped);
        Assert.NotNull(inside);
        Assert.Equal(parent.Id, inside.ParentId);
        Assert.Same(parent, Activity.Current);
        if (outcome == "success") { pending.SetResult(null); Assert.Null(await operation); }
        else if (outcome == "failure")
        {
            var error = new InvalidOperationException("Deferred failure");
            pending.SetException(error);
            Assert.Same(error, await Assert.ThrowsAsync<InvalidOperationException>(() => operation));
        }
        else
        {
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            pending.SetCanceled(cancellation.Token);
            var error = await Assert.ThrowsAsync<TaskCanceledException>(() => operation);
            Assert.Equal(cancellation.Token, error.CancellationToken);
        }
        var completed = Assert.Single(stopped);
        Assert.Same(inside, completed);
        Assert.Equal(outcome == "success" ? ActivityStatusCode.Ok : ActivityStatusCode.Error, completed.Status);
        Assert.Same(parent, Activity.Current);
    }
}
