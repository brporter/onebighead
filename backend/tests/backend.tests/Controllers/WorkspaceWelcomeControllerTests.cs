using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class WorkspaceWelcomeControllerTests
{
    private readonly Mock<IWorkspaceWelcome> _welcome = new(MockBehavior.Strict);

    [Theory]
    [InlineData(null, "2")]
    [InlineData("invalid", "2")]
    [InlineData("0", "2")]
    [InlineData("-1", "2")]
    [InlineData("1", null)]
    [InlineData("1", "invalid")]
    [InlineData("1", "0")]
    [InlineData("1", "-1")]
    public async Task InvalidIdentity_DoesNotCompleteWelcome(string? user, string? workspace)
    {
        Assert.IsType<UnauthorizedResult>(await Controller(user, workspace).CompleteWelcome(new()));
        _welcome.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(WorkspaceWelcomeStatus.Completed, typeof(OkObjectResult))]
    [InlineData(WorkspaceWelcomeStatus.NotFound, typeof(NotFoundObjectResult))]
    [InlineData(WorkspaceWelcomeStatus.Forbidden, typeof(ForbidResult))]
    [InlineData(WorkspaceWelcomeStatus.Invalid, typeof(BadRequestObjectResult))]
    [InlineData(WorkspaceWelcomeStatus.Conflict, typeof(ConflictObjectResult))]
    public async Task Complete_MapsCurrentAuthorizationAndTransactionOutcomes(WorkspaceWelcomeStatus status, Type expected)
    {
        var request = new CompleteWelcomeRequest { WorkspaceName = "Library" };
        var response = new CompleteWelcomeResponse { WorkspaceId = 2, WorkspaceName = "Library", HasCompletedWelcome = true };
        _welcome.Setup(w => w.CompleteAsync(1, 2, request)).ReturnsAsync(new WorkspaceWelcomeResult(status, response, "Review setup"));
        var controller = Controller("1", "2");
        var result = await controller.CompleteWelcome(request);
        Assert.IsType(expected, result);
        if (result is OkObjectResult success) Assert.Same(response, success.Value);
        else if (result is ObjectResult failure) Assert.Contains("Review setup", System.Text.Json.JsonSerializer.Serialize(failure.Value));
        Assert.Equal(0, controller.Response.Headers.SetCookie.Count);
        _welcome.Verify(w => w.CompleteAsync(1, 2, request), Times.Once);
    }

    private WorkspaceWelcomeController Controller(string? user, string? workspace)
    {
        var claims = new List<Claim>();
        if (user is not null) claims.Add(new(ClaimTypes.NameIdentifier, user));
        if (workspace is not null) claims.Add(new(ClaimNames.WorkspaceId, workspace));
        return new(_welcome.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Test")) }
            }
        };
    }
}
