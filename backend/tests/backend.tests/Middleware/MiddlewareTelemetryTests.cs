using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using OneBigHead.Server.Middleware;
using OneBigHead.Server.Services.Workspaces;
using OneBigHead.Server.Telemetry;
using OneBigHead.Server.Tests.Hosting;

namespace OneBigHead.Server.Tests.Middleware;

// ActivitySource listeners are process-wide. These cases must run without
// another test's listener turning sampling on for the disabled cases.
[Collection(TelemetryConfigurationCollection.Name)]
public class MiddlewareTelemetryTests
{
    [Theory]
    [InlineData(false, "skipped", 200)]
    [InlineData(true, "skipped", 200)]
    [InlineData(false, "user_deleted", 401)]
    [InlineData(true, "user_deleted", 401)]
    [InlineData(false, "no_active_workspaces", 401)]
    [InlineData(true, "no_active_workspaces", 401)]
    [InlineData(false, "workspace_deleted", 410)]
    [InlineData(true, "workspace_deleted", 410)]
    [InlineData(false, "passed", 200)]
    [InlineData(true, "passed", 200)]
    public async Task WorkspaceChecks_KeepTheirBehaviorWithTracingEnabledOrDisabled(bool trace, string outcome, int status)
    {
        var completed = new List<Activity>();
        var source = DiagnosticsConfig.AppActivitySource;
        using var listener = new ActivityListener
        {
            ShouldListenTo = candidate => candidate == source,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => trace ? ActivitySamplingResult.AllDataAndRecorded : ActivitySamplingResult.None,
            ActivityStopped = completed.Add
        };
        ActivitySource.AddActivityListener(listener);
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/items";
        context.Response.Body = new MemoryStream();
        context.User = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, "1"), new Claim("workspace_id", "2")], "test"));
        context.SetEndpoint(new Endpoint(_ => Task.CompletedTask,
            outcome == "skipped" ? new EndpointMetadataCollection(new AllowInactiveWorkspaceAttribute()) : EndpointMetadataCollection.Empty,
            "Test endpoint"));
        var service = new Mock<IWorkspaceAccessService>();
        service.Setup(s => s.IsUserDeletedAsync(1)).ReturnsAsync(outcome == "user_deleted");
        service.Setup(s => s.HasUserAnyActiveWorkspaceAsync(1)).ReturnsAsync(outcome != "no_active_workspaces");
        service.Setup(s => s.IsWorkspaceDeletedAsync(2)).ReturnsAsync(outcome == "workspace_deleted");
        var nextCalls = 0;
        await new WorkspaceActiveMiddleware(_ => { nextCalls++; return Task.CompletedTask; }, NullLogger<WorkspaceActiveMiddleware>.Instance)
            .InvokeAsync(context, service.Object);

        Assert.Equal(status, context.Response.StatusCode);
        Assert.Equal(status == 200 ? 1 : 0, nextCalls);
        if (trace)
        {
            var activity = Assert.Single(completed);
            Assert.Equal(nameof(WorkspaceActiveMiddleware), activity.DisplayName);
            Assert.Equal(outcome, activity.GetTagItem("workspace_check.outcome"));
            if (outcome is "user_deleted" or "no_active_workspaces") Assert.Equal(1, activity.GetTagItem("user_id"));
            if (outcome is "workspace_deleted" or "passed") Assert.Equal(2, activity.GetTagItem("workspace_id"));
        }
        else Assert.Empty(completed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExceptionHandling_RecordsAnErrorWhenAnActivityExistsWithoutLeakingDetails(bool trace)
    {
        var previous = Activity.Current;
        Activity.Current = null;
        try
        {
            using var activity = trace ? new Activity("request").Start() : null;
            var context = new DefaultHttpContext();
            context.Response.Body = new MemoryStream();
            var environment = Mock.Of<IHostEnvironment>(e => e.EnvironmentName == "Production");
            var failure = new Exception("Internal database connection details");
            var handled = await new GlobalExceptionHandler(NullLogger<GlobalExceptionHandler>.Instance, environment)
                .TryHandleAsync(context, failure, CancellationToken.None);

            Assert.True(handled);
            Assert.Equal(500, context.Response.StatusCode);
            context.Response.Body.Position = 0;
            Assert.DoesNotContain(failure.Message, await new StreamReader(context.Response.Body).ReadToEndAsync());
            if (trace)
            {
                Assert.Equal(ActivityStatusCode.Error, activity!.Status);
                Assert.Equal(failure.Message, activity.StatusDescription);
                Assert.Contains(activity.Events, entry => entry.Name == "exception" &&
                    entry.Tags.Any(tag => tag.Key == "exception.message" && Equals(tag.Value, failure.Message)));
            }
        }
        finally { Activity.Current = previous; }
    }
}
