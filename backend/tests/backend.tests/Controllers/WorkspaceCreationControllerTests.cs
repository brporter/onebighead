using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class WorkspaceCreationControllerTests
{
    private readonly Mock<IWorkspaceCreation> _creation = new(MockBehavior.Strict);

    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    [InlineData("0")]
    [InlineData("-1")]
    public async Task InvalidIdentity_DoesNotCreateWorkspace(string? id)
    {
        Assert.IsType<UnauthorizedResult>(await Controller(id).CreateWorkspace(new() { Name = "Library" }));
        _creation.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(WorkspaceCreationStatus.Created, typeof(OkObjectResult))]
    [InlineData(WorkspaceCreationStatus.Forbidden, typeof(ForbidResult))]
    [InlineData(WorkspaceCreationStatus.Invalid, typeof(BadRequestObjectResult))]
    [InlineData(WorkspaceCreationStatus.Conflict, typeof(ConflictObjectResult))]
    public async Task Creation_MapsResultsWithoutSwitchingSession(WorkspaceCreationStatus status, Type expected)
    {
        var request = new CreateWorkspaceRequest { Name = "Library" };
        var workspace = new CreateWorkspaceResponse { WorkspaceId = 3, WorkspaceName = "Library" };
        _creation.Setup(c => c.CreateAsync(1, request)).ReturnsAsync(new WorkspaceCreationResult(status, workspace, "Review workspace"));
        var controller = Controller("1");
        var result = await controller.CreateWorkspace(request);
        Assert.IsType(expected, result);
        if (result is OkObjectResult success) Assert.Same(workspace, success.Value);
        else if (result is ObjectResult error) Assert.Contains("Review workspace", System.Text.Json.JsonSerializer.Serialize(error.Value));
        Assert.Equal(0, controller.Response.Headers.SetCookie.Count);
        _creation.Verify(c => c.CreateAsync(1, request), Times.Once);
    }

    private WorkspaceCreationController Controller(string? id) => new(_creation.Object)
    {
        ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(id is null ? [] : [new Claim(ClaimTypes.NameIdentifier, id)], "Test")) }
        }
    };
}
