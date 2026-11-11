using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Memberships;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class TeamMembershipControllerTests
{
    private readonly Mock<ITeamRoleChanges> _roles = new(MockBehavior.Strict);
    private readonly Mock<ITeamMemberRemoval> _removal = new(MockBehavior.Strict);

    [Theory]
    [InlineData(null, "1")]
    [InlineData("bad", "1")]
    [InlineData("0", "1")]
    [InlineData("-1", "1")]
    [InlineData("1", null)]
    [InlineData("1", "bad")]
    [InlineData("1", "0")]
    [InlineData("1", "-1")]
    public async Task InvalidIdentity_DoesNotReachEitherCommand(string? userId, string? workspaceId)
    {
        var controller = Controller(userId, workspaceId);
        Assert.IsType<UnauthorizedResult>(await controller.UpdateUserRole(2, new() { Role = WorkspaceRole.WorkspaceAdmin }));
        Assert.IsType<UnauthorizedResult>(await controller.RemoveUser(2));
        _roles.VerifyNoOtherCalls();
        _removal.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(TeamMembershipStatus.Changed, typeof(NoContentResult))]
    [InlineData(TeamMembershipStatus.NotFound, typeof(NotFoundObjectResult))]
    [InlineData(TeamMembershipStatus.Forbidden, typeof(ForbidResult))]
    [InlineData(TeamMembershipStatus.Invalid, typeof(BadRequestObjectResult))]
    [InlineData(TeamMembershipStatus.Conflict, typeof(ConflictObjectResult))]
    public async Task Commands_UseCurrentIdentityAndMapResults(TeamMembershipStatus status, Type expected)
    {
        var outcome = new TeamMembershipResult(status, "Review membership");
        _roles.Setup(r => r.ChangeRoleAsync(1, 3, 2, WorkspaceRole.WorkspaceAdmin)).ReturnsAsync(outcome);
        _removal.Setup(r => r.RemoveAsync(1, 3, 2)).ReturnsAsync(outcome);
        var controller = Controller("1", "3");
        var role = await controller.UpdateUserRole(2, new() { Role = WorkspaceRole.WorkspaceAdmin });
        var removal = await controller.RemoveUser(2);
        Assert.IsType(expected, role);
        Assert.IsType(expected, removal);
        if (role is ObjectResult body) Assert.Contains("Review membership", System.Text.Json.JsonSerializer.Serialize(body.Value));
        Assert.Equal(0, controller.Response.Headers.SetCookie.Count);
        _roles.Verify(r => r.ChangeRoleAsync(1, 3, 2, WorkspaceRole.WorkspaceAdmin), Times.Once);
        _removal.Verify(r => r.RemoveAsync(1, 3, 2), Times.Once);
    }

    private TeamMembershipController Controller(string? userId, string? workspaceId)
    {
        var claims = new List<Claim>();
        if (userId is not null) claims.Add(new(ClaimTypes.NameIdentifier, userId));
        if (workspaceId is not null) claims.Add(new("workspace_id", workspaceId));
        return new(_roles.Object, _removal.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Test")) }
            }
        };
    }
}
