using System.Diagnostics;
using Moq;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Tests.Unit.Services;

[Trait("Category", "Unit")]
public class WorkspaceDeletionTelemetryTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Tracing_PreservesDeletionResultsAndExceptionsWithOrWithoutAListener(bool enabled, bool fails)
    {
        using var source = new ActivitySource($"WorkspaceDeletionTests.{Guid.NewGuid()}");
        var stopped = new List<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = candidate => enabled && ReferenceEquals(candidate, source),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = stopped.Add
        };
        ActivitySource.AddActivityListener(listener);
        var inner = new Mock<IWorkspaceDeletionService>(MockBehavior.Strict);
        var outcome = new WorkspaceDeletionResult(WorkspaceDeletionStatus.Conflict, Error: "Review deletion");
        var failure = new InvalidOperationException("Storage unavailable");
        if (fails) inner.Setup(s => s.SoftDeleteWorkspaceAsync(3, 7)).ThrowsAsync(failure);
        else inner.Setup(s => s.SoftDeleteWorkspaceAsync(3, 7)).ReturnsAsync(outcome);
        var proxy = new TracingProxy_IWorkspaceDeletionService(inner.Object, source);
        if (fails) Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() => proxy.SoftDeleteWorkspaceAsync(3, 7)));
        else Assert.Same(outcome, await proxy.SoftDeleteWorkspaceAsync(3, 7));
        inner.Verify(s => s.SoftDeleteWorkspaceAsync(3, 7), Times.Once);
        if (!enabled) Assert.Empty(stopped);
        else
        {
            var activity = Assert.Single(stopped);
            Assert.Equal("IWorkspaceDeletionService.SoftDeleteWorkspaceAsync", activity.OperationName);
            Assert.Equal(ActivityKind.Internal, activity.Kind);
            Assert.Equal("SoftDeleteWorkspaceAsync", activity.GetTagItem("code.function"));
            Assert.Equal("OneBigHead.Server.Services.Workspaces.IWorkspaceDeletionService", activity.GetTagItem("code.namespace"));
            Assert.Equal(3, activity.GetTagItem("workspace_id"));
            Assert.Equal(7, activity.GetTagItem("deleted_by_user_id"));
            Assert.Equal(fails ? ActivityStatusCode.Error : ActivityStatusCode.Ok, activity.Status);
            if (fails)
            {
                Assert.Equal(failure.Message, activity.StatusDescription);
                Assert.Equal("exception", Assert.Single(activity.Events).Name);
            }
            else Assert.Empty(activity.Events);
        }
    }
}
