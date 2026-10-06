using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using OneBigHead.Server.Middleware;
using OneBigHead.Server.Services;

namespace OneBigHead.Server.Tests.Middleware;

[Trait("Category", "Unit")]
public class WorkspaceActiveMiddlewareTests
{
    [Theory]
    [InlineData(true, false, true, false, 200, "")]
    [InlineData(false, true, true, false, 401, "USER_DELETED")]
    [InlineData(false, false, false, false, 401, "NO_ACTIVE_WORKSPACES")]
    [InlineData(false, false, true, true, 410, "WORKSPACE_DELETED")]
    [InlineData(false, false, true, false, 200, "")]
    public async Task AppliesWorkspaceChecksUnlessEndpointOptsOut(bool exempt, bool userDeleted, bool hasWorkspace, bool workspaceDeleted, int status, string code)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/auth-not-a-real-exemption";
        context.Response.Body = new MemoryStream();
        context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "1"), new Claim("workspace_id", "2")], "test"));
        if (exempt) context.SetEndpoint(new Endpoint(_ => Task.CompletedTask, new EndpointMetadataCollection(new AllowInactiveWorkspaceAttribute()), "Recovery"));
        var service = new Mock<IWorkspaceService>();
        service.Setup(s => s.IsUserDeletedAsync(1)).ReturnsAsync(userDeleted);
        service.Setup(s => s.HasUserAnyActiveWorkspaceAsync(1)).ReturnsAsync(hasWorkspace);
        service.Setup(s => s.IsWorkspaceDeletedAsync(2)).ReturnsAsync(workspaceDeleted);
        var nextCalled = false;
        var middleware = new WorkspaceActiveMiddleware(_ => { nextCalled = true; return Task.CompletedTask; }, NullLogger<WorkspaceActiveMiddleware>.Instance);
        await middleware.InvokeAsync(context, service.Object);
        Assert.Equal(status, context.Response.StatusCode);
        Assert.Equal(status == 200, nextCalled);
        if (exempt) service.VerifyNoOtherCalls();
        if (status != 200)
        {
            Assert.Equal("no-store", context.Response.Headers.CacheControl);
            context.Response.Body.Position = 0;
            Assert.Contains(code, await new StreamReader(context.Response.Body).ReadToEndAsync());
        }
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("invalid", "invalid")]
    [InlineData("", "")]
    public async Task MissingOrInvalidClaims_ContinueToEndpointAuthorization(string? userId, string? workspaceId)
    {
        var context = new DefaultHttpContext();
        var claims = new List<Claim>();
        if (userId is not null) claims.Add(new(ClaimTypes.NameIdentifier, userId));
        if (workspaceId is not null) claims.Add(new("workspace_id", workspaceId));
        context.User = new ClaimsPrincipal(new ClaimsIdentity(claims));
        var called = false;
        await new WorkspaceActiveMiddleware(_ => { called = true; return Task.CompletedTask; }, NullLogger<WorkspaceActiveMiddleware>.Instance)
            .InvokeAsync(context, Mock.Of<IWorkspaceService>());
        Assert.True(called);
    }
}
