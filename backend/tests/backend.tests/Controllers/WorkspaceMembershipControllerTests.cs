using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Moq;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Memberships;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class WorkspaceMembershipControllerTests
{
    private readonly Mock<IWorkspaceAdminTransfer> _transfer = new(MockBehavior.Strict);
    private readonly Mock<IWorkspaceLeave> _leave = new(MockBehavior.Strict);
    private readonly Mock<IWorkspaceSwitch> _switch = new(MockBehavior.Strict);
    private readonly Mock<ITokenService> _tokens = new(MockBehavior.Strict);

    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    [InlineData("0")]
    [InlineData("-1")]
    public async Task InvalidIdentity_DoesNotInvokeCommandOrIssueCookie(string? id)
    {
        var controller = Controller(id);
        Assert.IsType<UnauthorizedResult>((await controller.TransferAdmin(1, new() { NewAdminUserId = 2 })).Result);
        Assert.IsType<UnauthorizedResult>(await controller.LeaveWorkspace(1));
        Assert.IsType<UnauthorizedResult>(await controller.SwitchWorkspace(1));
        Assert.Equal(0, controller.Response.Headers.SetCookie.Count);
        _transfer.VerifyNoOtherCalls();
        _leave.VerifyNoOtherCalls();
        _switch.VerifyNoOtherCalls();
        _tokens.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(WorkspaceAdminTransferStatus.NotFound, typeof(NotFoundObjectResult))]
    [InlineData(WorkspaceAdminTransferStatus.Forbidden, typeof(ForbidResult))]
    [InlineData(WorkspaceAdminTransferStatus.Invalid, typeof(BadRequestObjectResult))]
    [InlineData(WorkspaceAdminTransferStatus.Conflict, typeof(ConflictObjectResult))]
    public async Task Failure_MapsTheCommandWithoutChangingCookie(WorkspaceAdminTransferStatus status, Type expected)
    {
        _transfer.Setup(t => t.TransferAsync(1, 3, 2)).ReturnsAsync(new WorkspaceAdminTransferResult(status, "Review members"));
        var controller = Controller("1");
        var result = (await controller.TransferAdmin(3, new() { NewAdminUserId = 2 })).Result;
        Assert.IsType(expected, result);
        if (result is ObjectResult body)
        {
            var response = Assert.IsType<TransferAdminResponse>(body.Value);
            Assert.False(response.Success);
            Assert.Equal("Review members", response.Error);
        }
        Assert.Equal(0, controller.Response.Headers.SetCookie.Count);
        _tokens.VerifyNoOtherCalls();
        _transfer.Verify(t => t.TransferAsync(1, 3, 2), Times.Once);
    }

    [Theory]
    [InlineData(3, WorkspaceRole.Normal)]
    [InlineData(4, WorkspaceRole.WorkspaceAdmin)]
    [InlineData(null, WorkspaceRole.Normal)]
    public async Task Success_IssuesCookieFromCommittedActiveWorkspaceSnapshot(int? activeId, WorkspaceRole role)
    {
        var user = new User { Id = 1, ActiveWorkspaceId = activeId, Email = "owner@example.test" };
        if (activeId.HasValue) user.WorkspaceMemberships.Add(new WorkspaceUser
        {
            UserId = 1, WorkspaceId = activeId.Value, WorkspaceRole = role,
            Workspace = new Workspace { Id = activeId.Value, Name = "Active" }
        });
        var session = new CurrentUserSession(user, CurrentUserResponse.FromUser(user));
        _transfer.Setup(t => t.TransferAsync(1, 3, 2)).ReturnsAsync(new WorkspaceAdminTransferResult(WorkspaceAdminTransferStatus.Transferred, Session: session));
        _tokens.Setup(t => t.GenerateAppToken(user, role)).Returns("fresh-session");
        var controller = Controller("1");
        var response = Assert.IsType<TransferAdminResponse>(Assert.IsType<OkObjectResult>((await controller.TransferAdmin(3, new() { NewAdminUserId = 2 })).Result).Value);
        Assert.True(response.Success);
        Assert.Null(response.Error);
        Assert.Contains("fresh-session", controller.Response.Headers.SetCookie.ToString());
        _tokens.Verify(t => t.GenerateAppToken(user, role), Times.Once);
    }

    [Theory]
    [InlineData(WorkspaceLeaveStatus.NotFound, typeof(NotFoundObjectResult))]
    [InlineData(WorkspaceLeaveStatus.Invalid, typeof(BadRequestObjectResult))]
    [InlineData(WorkspaceLeaveStatus.Conflict, typeof(ConflictObjectResult))]
    public async Task LeaveFailure_PreservesCookieAndReturnsReviewMessage(WorkspaceLeaveStatus status, Type expected)
    {
        _leave.Setup(l => l.LeaveAsync(1, 3)).ReturnsAsync(new WorkspaceLeaveResult(status, "Review workspaces"));
        var controller = Controller("1");
        var result = await controller.LeaveWorkspace(3);
        Assert.IsType(expected, result);
        Assert.Contains("Review workspaces", System.Text.Json.JsonSerializer.Serialize(((ObjectResult)result).Value));
        Assert.Equal(0, controller.Response.Headers.SetCookie.Count);
        _tokens.VerifyNoOtherCalls();
        _leave.Verify(l => l.LeaveAsync(1, 3), Times.Once);
    }

    [Fact]
    public async Task LeaveSuccess_IssuesTheReplacementWorkspaceCookie()
    {
        var user = new User { Id = 1, ActiveWorkspaceId = 4, Email = "owner@example.test", WorkspaceMemberships =
            [new WorkspaceUser { UserId = 1, WorkspaceId = 4, WorkspaceRole = WorkspaceRole.WorkspaceAdmin, Workspace = new Workspace { Id = 4, Name = "Remaining" } }] };
        var session = CurrentUserSession.FromUser(user);
        _leave.Setup(l => l.LeaveAsync(1, 3)).ReturnsAsync(new WorkspaceLeaveResult(WorkspaceLeaveStatus.Left, Session: session));
        _tokens.Setup(t => t.GenerateAppToken(user, WorkspaceRole.WorkspaceAdmin)).Returns("remaining-workspace-token");
        var controller = Controller("1");
        Assert.True(Assert.IsType<LeaveWorkspaceResponse>(Assert.IsType<OkObjectResult>(await controller.LeaveWorkspace(3)).Value).Success);
        Assert.Contains("remaining-workspace-token", controller.Response.Headers.SetCookie.ToString());
        _tokens.Verify(t => t.GenerateAppToken(user, WorkspaceRole.WorkspaceAdmin), Times.Once);
    }

    [Theory]
    [InlineData(WorkspaceSwitchStatus.Forbidden, typeof(ForbidResult))]
    [InlineData(WorkspaceSwitchStatus.Conflict, typeof(ConflictObjectResult))]
    public async Task SwitchFailure_PreservesCookie(WorkspaceSwitchStatus status, Type expected)
    {
        _switch.Setup(s => s.SwitchAsync(1, 3)).ReturnsAsync(new WorkspaceSwitchResult(status, "Review workspaces"));
        var controller = Controller("1");
        var result = await controller.SwitchWorkspace(3);
        Assert.IsType(expected, result);
        if (result is ObjectResult body) Assert.Contains("Review workspaces", System.Text.Json.JsonSerializer.Serialize(body.Value));
        Assert.Equal(0, controller.Response.Headers.SetCookie.Count);
        _tokens.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task SwitchSuccess_IssuesCookieFromTheCommittedTargetMembership()
    {
        var user = new User { Id = 1, ActiveWorkspaceId = 3, Email = "owner@example.test", WorkspaceMemberships =
            [new WorkspaceUser { UserId = 1, WorkspaceId = 3, WorkspaceRole = WorkspaceRole.Normal, Workspace = new Workspace { Id = 3, Name = "Target" } }] };
        _switch.Setup(s => s.SwitchAsync(1, 3)).ReturnsAsync(new WorkspaceSwitchResult(WorkspaceSwitchStatus.Switched, Session: CurrentUserSession.FromUser(user)));
        _tokens.Setup(t => t.GenerateAppToken(user, WorkspaceRole.Normal)).Returns("target-cookie");
        var controller = Controller("1");
        var response = Assert.IsType<SwitchWorkspaceResponse>(Assert.IsType<OkObjectResult>(await controller.SwitchWorkspace(3)).Value);
        Assert.True(response.Success);
        Assert.Equal(3, response.WorkspaceId);
        Assert.Equal("Target", response.WorkspaceName);
        Assert.Contains("target-cookie", controller.Response.Headers.SetCookie.ToString());
    }

    private WorkspaceMembershipController Controller(string? userId) => new(_transfer.Object, _leave.Object, _switch.Object, _tokens.Object, Options.Create(new AuthenticationSettings()))
    {
        ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(userId is null ? [] : [new Claim(ClaimTypes.NameIdentifier, userId)], "Test"))
            }
        }
    };
}
