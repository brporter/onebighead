using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services.Memberships;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class TeamDirectoryControllerTests
{
    private readonly Mock<ITeamDirectory> _directory = new(MockBehavior.Strict);
    private readonly Mock<ITeamInvitations> _invitations = new(MockBehavior.Strict);

    [Theory]
    [InlineData(null, "1")]
    [InlineData("bad", "1")]
    [InlineData("0", "1")]
    [InlineData("-1", "1")]
    [InlineData("1", null)]
    [InlineData("1", "bad")]
    [InlineData("1", "0")]
    [InlineData("1", "-1")]
    public async Task InvalidIdentity_DoesNotReachEitherPort(string? userId, string? workspaceId)
    {
        var controller = Controller(userId, workspaceId);
        Assert.IsType<UnauthorizedResult>(await controller.GetUsers());
        Assert.IsType<UnauthorizedResult>(await controller.InviteUser(new()));
        _directory.VerifyNoOtherCalls();
        _invitations.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Read_UsesCurrentIdentityAndMapsAccess(bool allowed)
    {
        IReadOnlyList<WorkspaceUserResponse>? members = allowed ? [new() { UserId = 2, Email = "team@example.test" }] : null;
        _directory.Setup(d => d.ReadAsync(1, 3)).ReturnsAsync(members);
        var response = await Controller("1", "3").GetUsers();
        if (allowed) Assert.Same(members, Assert.IsType<OkObjectResult>(response).Value);
        else Assert.IsType<ForbidResult>(response);
        _directory.Verify(d => d.ReadAsync(1, 3), Times.Once);
    }

    [Theory]
    [InlineData(TeamInvitationStatus.Created, typeof(CreatedAtActionResult))]
    [InlineData(TeamInvitationStatus.Forbidden, typeof(ForbidResult))]
    [InlineData(TeamInvitationStatus.Invalid, typeof(BadRequestObjectResult))]
    [InlineData(TeamInvitationStatus.Conflict, typeof(ConflictObjectResult))]
    public async Task Invite_MapsOutcomeWithoutChangingActorSession(TeamInvitationStatus status, Type expected)
    {
        var request = new InviteUserRequest { Email = "team@example.test" };
        var member = new CreatedInvitationResponse(new(Guid.NewGuid(), request.Email, OneBigHead.Server.Models.WorkspaceRole.Normal, DateTime.UtcNow, DateTime.UtcNow.AddDays(7)), "private-token");
        _invitations.Setup(i => i.InviteAsync(1, 3, request)).ReturnsAsync(new TeamInvitationResult(status, member, "Review invitation"));
        var controller = Controller("1", "3");
        var response = await controller.InviteUser(request);
        Assert.IsType(expected, response);
        if (response is CreatedAtActionResult created)
        {
            Assert.Equal(nameof(TeamDirectoryController.GetUsers), created.ActionName);
            Assert.Same(member, created.Value);
        }
        else if (response is ObjectResult error) Assert.Contains("Review invitation", System.Text.Json.JsonSerializer.Serialize(error.Value));
        Assert.Equal(0, controller.Response.Headers.SetCookie.Count);
        _invitations.Verify(i => i.InviteAsync(1, 3, request), Times.Once);
    }

    private TeamDirectoryController Controller(string? userId, string? workspaceId)
    {
        var claims = new List<Claim>();
        if (userId is not null) claims.Add(new(ClaimTypes.NameIdentifier, userId));
        if (workspaceId is not null) claims.Add(new("workspace_id", workspaceId));
        return new(_directory.Object, _invitations.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Test")) }
            }
        };
    }
}
