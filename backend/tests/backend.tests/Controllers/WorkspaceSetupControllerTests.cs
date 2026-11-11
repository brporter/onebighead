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
public class WorkspaceSetupControllerTests
{
    private readonly Mock<IWorkspaceSetup> _setup = new(MockBehavior.Strict);
    private readonly Mock<ITokenService> _tokens = new(MockBehavior.Strict);

    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    [InlineData("0")]
    [InlineData("-1")]
    public async Task InvalidIdentity_DoesNotCreateAWorkspace(string? identity)
    {
        Assert.IsType<UnauthorizedResult>(await Controller(identity).SetupWorkspace(new()));
        _setup.VerifyNoOtherCalls();
        _tokens.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(WorkspaceSetupStatus.Forbidden, typeof(ForbidResult))]
    [InlineData(WorkspaceSetupStatus.Invalid, typeof(BadRequestObjectResult))]
    [InlineData(WorkspaceSetupStatus.Conflict, typeof(ConflictObjectResult))]
    [InlineData(WorkspaceSetupStatus.Unavailable, typeof(ObjectResult))]
    public async Task FailedSetup_ReturnsItsOutcomeWithoutReplacingTheCookie(WorkspaceSetupStatus status, Type expected)
    {
        var request = new SetupWorkspaceRequest { WorkspaceName = "Library" };
        _setup.Setup(s => s.CreateAsync(1, request)).ReturnsAsync(new WorkspaceSetupResult(status, Error: "Review setup"));
        var controller = Controller("1");
        var response = await controller.SetupWorkspace(request);
        Assert.IsType(expected, response);
        if (response is ObjectResult error) Assert.Contains("Review setup", System.Text.Json.JsonSerializer.Serialize(error.Value));
        if (status == WorkspaceSetupStatus.Unavailable) Assert.Equal(410, ((ObjectResult)response).StatusCode);
        Assert.Equal(0, controller.Response.Headers.SetCookie.Count);
        _tokens.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(WorkspaceRole.Normal)]
    [InlineData(WorkspaceRole.WorkspaceAdmin)]
    public async Task Success_UsesTheCommittedSessionForItsCookie(WorkspaceRole role)
    {
        var request = new SetupWorkspaceRequest { WorkspaceName = "Library" };
        var user = new User { Id = 1, ActiveWorkspaceId = 9, WorkspaceMemberships =
            [new() { WorkspaceId = 9, WorkspaceRole = role, Workspace = new() { Id = 9, Name = "Library" } }] };
        var session = CurrentUserSession.FromUser(user);
        var workspace = new SetupWorkspaceResponse { WorkspaceId = 9, CollectionId = 12, WorkspaceName = "Library", CollectionName = "Books", WorkspaceRole = role };
        _setup.Setup(s => s.CreateAsync(1, request)).ReturnsAsync(new WorkspaceSetupResult(WorkspaceSetupStatus.Created, workspace, session));
        _tokens.Setup(t => t.GenerateAppToken(user, role)).Returns("committed-session");
        var controller = Controller("1");
        Assert.Same(workspace, Assert.IsType<OkObjectResult>(await controller.SetupWorkspace(request)).Value);
        Assert.Contains(controller.Response.Headers.SetCookie, cookie => cookie!.Contains("committed-session"));
        _tokens.Verify(t => t.GenerateAppToken(user, role), Times.Once);
        _tokens.VerifyNoOtherCalls();
    }

    private WorkspaceSetupController Controller(string? identity) => new(_setup.Object, _tokens.Object, Options.Create(new AuthenticationSettings()))
    {
        ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(identity is null ? [] : [new Claim(ClaimTypes.NameIdentifier, identity)], "Test")) }
        }
    };
}
