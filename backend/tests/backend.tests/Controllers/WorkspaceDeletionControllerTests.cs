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
public class WorkspaceDeletionControllerTests
{
    private readonly Mock<IWorkspaceDeletionService> _deletion = new(MockBehavior.Strict);
    private readonly Mock<ITokenService> _tokens = new(MockBehavior.Strict);
    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    [InlineData("0")]
    [InlineData("-1")]
    public async Task InvalidIdentity_CannotDelete(string? id)
    {
        Assert.IsType<UnauthorizedResult>(await Controller(id).DeleteWorkspace(2));
        _deletion.VerifyNoOtherCalls();
        _tokens.VerifyNoOtherCalls();
    }
    [Theory]
    [InlineData(WorkspaceDeletionStatus.NotFound, typeof(NotFoundObjectResult))]
    [InlineData(WorkspaceDeletionStatus.Forbidden, typeof(ForbidResult))]
    [InlineData(WorkspaceDeletionStatus.Conflict, typeof(ConflictObjectResult))]
    public async Task RejectedDeletion_PreservesCookie(WorkspaceDeletionStatus status, Type type)
    {
        _deletion.Setup(d => d.SoftDeleteWorkspaceAsync(2, 1)).ReturnsAsync(new WorkspaceDeletionResult(status, Error: "Review deletion"));
        var controller = Controller("1");
        var result = await controller.DeleteWorkspace(2);
        Assert.IsType(type, result);
        if (result is ObjectResult body) Assert.Contains("Review deletion", System.Text.Json.JsonSerializer.Serialize(body.Value));
        Assert.Equal(0, controller.Response.Headers.SetCookie.Count);
        _tokens.VerifyNoOtherCalls();
    }
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task CompletedDeletion_ExpiresOrReplacesTheCookieFromItsCommittedSnapshot(bool deletedUser)
    {
        var user = new User { Id = 1, ActiveWorkspaceId = 3, Email = "owner@example.test", WorkspaceMemberships =
            [new WorkspaceUser { UserId = 1, WorkspaceId = 3, WorkspaceRole = WorkspaceRole.Normal, Workspace = new Workspace { Id = 3, Name = "Remaining" } }] };
        var response = new WorkspaceDeletionResponse { Success = true, UserSoftDeleted = deletedUser };
        _deletion.Setup(d => d.SoftDeleteWorkspaceAsync(2, 1)).ReturnsAsync(new WorkspaceDeletionResult(WorkspaceDeletionStatus.Deleted, response, deletedUser ? null : CurrentUserSession.FromUser(user)));
        if (!deletedUser) _tokens.Setup(t => t.GenerateAppToken(user, WorkspaceRole.Normal)).Returns("current-session");
        var controller = Controller("1");
        Assert.Same(response, Assert.IsType<OkObjectResult>(await controller.DeleteWorkspace(2)).Value);
        var cookie = Assert.Single(controller.Response.Headers.SetCookie)!;
        if (deletedUser)
        {
            Assert.StartsWith(new AuthenticationSettings().Cookie.Name + "=;", cookie);
            Assert.True(Microsoft.Net.Http.Headers.SetCookieHeaderValue.Parse(cookie).Expires < DateTimeOffset.UtcNow);
            _tokens.VerifyNoOtherCalls();
        }
        else Assert.Contains("current-session", cookie);
    }
    private WorkspaceDeletionController Controller(string? id) => new(_deletion.Object, _tokens.Object, Options.Create(new AuthenticationSettings()))
    {
        ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext
        { User = new ClaimsPrincipal(new ClaimsIdentity(id is null ? [] : [new Claim(ClaimTypes.NameIdentifier, id)], "Test")) } }
    };
}
