using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class WorkspaceDetailsControllerTests
{
    private readonly Mock<IWorkspaceDetails> _details = new(MockBehavior.Strict);

    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    [InlineData("0")]
    [InlineData("-1")]
    public async Task InvalidIdentity_DoesNotUpdateWorkspace(string? id)
    {
        Assert.IsType<UnauthorizedResult>(await Controller(id).UpdateWorkspace(2, new() { Name = "Library" }));
        _details.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(WorkspaceDetailsStatus.Updated, typeof(OkObjectResult))]
    [InlineData(WorkspaceDetailsStatus.NotFound, typeof(NotFoundObjectResult))]
    [InlineData(WorkspaceDetailsStatus.Forbidden, typeof(ForbidResult))]
    [InlineData(WorkspaceDetailsStatus.Invalid, typeof(BadRequestObjectResult))]
    [InlineData(WorkspaceDetailsStatus.Conflict, typeof(ConflictObjectResult))]
    public async Task Update_MapsCurrentAuthorizationAndWriteOutcomes(WorkspaceDetailsStatus status, Type expected)
    {
        var request = new UpdateWorkspaceRequest { Name = "Library" };
        var workspace = new UpdateWorkspaceResponse { WorkspaceId = 2, WorkspaceName = "Library" };
        _details.Setup(c => c.UpdateAsync(1, 2, request)).ReturnsAsync(new WorkspaceDetailsResult(status, workspace, "Review workspace"));
        var controller = Controller("1");
        var result = await controller.UpdateWorkspace(2, request);
        Assert.IsType(expected, result);
        if (result is OkObjectResult success) Assert.Same(workspace, success.Value);
        else if (result is ObjectResult error) Assert.Contains("Review workspace", System.Text.Json.JsonSerializer.Serialize(error.Value));
        Assert.Equal(0, controller.Response.Headers.SetCookie.Count);
        _details.Verify(c => c.UpdateAsync(1, 2, request), Times.Once);
    }

    private WorkspaceDetailsController Controller(string? id) => new(_details.Object)
    {
        ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(id is null ? [] : [new Claim(ClaimTypes.NameIdentifier, id)], "Test")) }
        }
    };
}
