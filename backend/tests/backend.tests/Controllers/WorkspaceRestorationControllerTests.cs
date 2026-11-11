using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Moq;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class WorkspaceRestorationControllerTests
{
    private readonly Mock<IWorkspaceRestorationService> _restoration = new(MockBehavior.Strict);
    private readonly Mock<ITokenService> _tokens = new(MockBehavior.Strict);
    private readonly WorkspaceRestorationController _controller;

    public WorkspaceRestorationControllerTests()
    {
        _controller = new(_restoration.Object, _tokens.Object, Options.Create(new AuthenticationSettings()))
        {
            ControllerContext = new() { HttpContext = new DefaultHttpContext() }
        };
        SetIdentity("7");
    }

    private void SetIdentity(string? id) => _controller.HttpContext.User = new ClaimsPrincipal(
        new ClaimsIdentity(id is null ? [] : [new Claim(ClaimTypes.NameIdentifier, id)], "Test"));

    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    public async Task BothEndpoints_RequireAValidUserIdentity(string? id)
    {
        SetIdentity(id);
        Assert.IsType<UnauthorizedResult>(await _controller.RestoreWorkspace(2, default));
        Assert.IsType<UnauthorizedResult>(await _controller.RestoreWorkspaces(new() { WorkspaceIds = [2] }, default));
        _restoration.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Batch_RejectsMissingSelections(bool isNull)
    {
        var request = new RestoreWorkspacesRequest { WorkspaceIds = isNull ? null! : [] };
        Assert.IsType<BadRequestObjectResult>(await _controller.RestoreWorkspaces(request, default));
        _restoration.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Batch_IssuesCookieForCommittedActiveWorkspace_AndForwardsCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        var user = new User { Id = 7, ActiveWorkspaceId = 3 };
        var selection = new List<int> { 3, 2 };
        _restoration.Setup(s => s.RestoreAndActivateAsync(7, selection, cancellation.Token))
            .ReturnsAsync(new WorkspaceRestorationResult(true, [new() { Id = 3 }, new() { Id = 2 }], user));
        _tokens.Setup(t => t.GenerateAppToken(user, WorkspaceRole.WorkspaceAdmin)).Returns("restored-token");

        var response = Assert.IsType<RestoreWorkspacesResponse>(Assert.IsType<OkObjectResult>(
            await _controller.RestoreWorkspaces(new() { WorkspaceIds = selection }, cancellation.Token)).Value);
        Assert.Equal(selection, response.RestoredWorkspaceIds);
        Assert.Equal(3, response.ActiveWorkspaceId);
        Assert.Contains(_controller.Response.Headers.SetCookie, c => c!.Contains("restored-token"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Batch_UnauthorizedOrUnchangedSelection_NeverIssuesACookie(bool authorized)
    {
        _restoration.Setup(s => s.RestoreAndActivateAsync(7, It.IsAny<IReadOnlyCollection<int>>(), default))
            .ReturnsAsync(new WorkspaceRestorationResult(authorized, [], null));
        var result = await _controller.RestoreWorkspaces(new() { WorkspaceIds = [2] }, default);
        if (authorized)
        {
            var response = Assert.IsType<RestoreWorkspacesResponse>(Assert.IsType<OkObjectResult>(result).Value);
            Assert.Empty(response.RestoredWorkspaceIds);
            Assert.Equal(0, response.ActiveWorkspaceId);
        }
        else Assert.IsType<ForbidResult>(result);
        Assert.Equal(0, _controller.Response.Headers.SetCookie.Count);
        _tokens.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Single_MapsAuthorizationAndDeletedState_WithoutChangingTheSession(bool authorized, bool restored)
    {
        using var cancellation = new CancellationTokenSource();
        _restoration.Setup(s => s.RestoreAsync(7, 2, cancellation.Token)).ReturnsAsync(new WorkspaceRestorationResult(
            authorized, restored ? [new() { Id = 2, Name = "Archive" }] : [], null));
        var result = await _controller.RestoreWorkspace(2, cancellation.Token);
        if (!authorized) Assert.IsType<ForbidResult>(result);
        else if (!restored) Assert.IsType<BadRequestObjectResult>(result);
        else
        {
            var response = Assert.IsType<RestoreWorkspaceResponse>(Assert.IsType<OkObjectResult>(result).Value);
            Assert.Equal(2, response.WorkspaceId);
            Assert.Equal("Archive", response.Name);
        }
        Assert.Equal(0, _controller.Response.Headers.SetCookie.Count);
        _tokens.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task FailedCommit_PropagatesToExceptionMiddleware_WithoutIssuingACookie()
    {
        var failure = new InvalidOperationException("Commit failed");
        _restoration.Setup(s => s.RestoreAndActivateAsync(7, It.IsAny<IReadOnlyCollection<int>>(), default)).ThrowsAsync(failure);
        Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _controller.RestoreWorkspaces(new() { WorkspaceIds = [2] }, default)));
        Assert.Equal(0, _controller.Response.Headers.SetCookie.Count);
        _tokens.VerifyNoOtherCalls();
    }
}
