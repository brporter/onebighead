using OneBigHead.Server.Authentication;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using System.Security.Claims;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class UsersControllerTests
{
    private const int TestWorkspaceId = 1;
    private const int TestUserId = 1;
    private const int OtherUserId = 2;

    private readonly Mock<IUserRepository> _mockUserRepository;
    private readonly Mock<IWorkspaceUserRepository> _mockWorkspaceUserRepository;
    private readonly Mock<IUserDeletionService> _mockUserDeletionService;
    private readonly Mock<IWorkspaceRepository> _mockWorkspaceRepository;
    private readonly Mock<ITokenRevocationService> _mockTokenRevocationService;
    private readonly UsersController _controller;

    public UsersControllerTests()
    {
        _mockUserRepository = new Mock<IUserRepository>();
        _mockWorkspaceUserRepository = new Mock<IWorkspaceUserRepository>();
        _mockUserDeletionService = new Mock<IUserDeletionService>();
        _mockWorkspaceRepository = new Mock<IWorkspaceRepository>();
        _mockTokenRevocationService = new Mock<ITokenRevocationService>();

        _controller = new UsersController(
            _mockUserRepository.Object,
            _mockWorkspaceUserRepository.Object,
            _mockUserDeletionService.Object,
            _mockWorkspaceRepository.Object,
            _mockTokenRevocationService.Object,
            Options.Create(new AuthenticationSettings()),
            new Mock<ILogger<UsersController>>().Object);

        var claims = new List<Claim>
        {
            new("workspace_id", TestWorkspaceId.ToString()),
            new(ClaimTypes.NameIdentifier, TestUserId.ToString()),
            new(ClaimTypes.Email, "test@example.com")
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(identity) }
        };
    }

    #region UpdateUserRole Tests

    [Fact]
    public async Task UpdateUserRole_Success_UpdatesRoleAndRevokesTokens()
    {
        _mockWorkspaceUserRepository
            .Setup(r => r.UpdateRoleWithAdminCheckAsync(OtherUserId, TestWorkspaceId, WorkspaceRole.Normal))
            .ReturnsAsync(AdminCheckResult.Success);

        var result = await _controller.UpdateUserRole(OtherUserId, new UpdateUserRoleRequest { Role = WorkspaceRole.Normal });

        Assert.IsType<NoContentResult>(result);
        _mockTokenRevocationService.Verify(s => s.RevokeAsync(OtherUserId), Times.Once);
    }

    [Fact]
    public async Task UpdateUserRole_OwnRole_ReturnsBadRequestWithoutRevoking()
    {
        var result = await _controller.UpdateUserRole(TestUserId, new UpdateUserRoleRequest { Role = WorkspaceRole.Normal });

        Assert.IsType<BadRequestObjectResult>(result);
        _mockTokenRevocationService.Verify(s => s.RevokeAsync(It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task UpdateUserRole_UserNotFound_ReturnsNotFoundWithoutRevoking()
    {
        _mockWorkspaceUserRepository
            .Setup(r => r.UpdateRoleWithAdminCheckAsync(OtherUserId, TestWorkspaceId, WorkspaceRole.Normal))
            .ReturnsAsync(AdminCheckResult.UserNotFound);

        var result = await _controller.UpdateUserRole(OtherUserId, new UpdateUserRoleRequest { Role = WorkspaceRole.Normal });

        Assert.IsType<NotFoundObjectResult>(result);
        _mockTokenRevocationService.Verify(s => s.RevokeAsync(It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task UpdateUserRole_WouldRemoveLastAdmin_ReturnsBadRequestWithoutRevoking()
    {
        _mockWorkspaceUserRepository
            .Setup(r => r.UpdateRoleWithAdminCheckAsync(OtherUserId, TestWorkspaceId, WorkspaceRole.Normal))
            .ReturnsAsync(AdminCheckResult.WouldRemoveLastAdmin);

        var result = await _controller.UpdateUserRole(OtherUserId, new UpdateUserRoleRequest { Role = WorkspaceRole.Normal });

        Assert.IsType<BadRequestObjectResult>(result);
        _mockTokenRevocationService.Verify(s => s.RevokeAsync(It.IsAny<int>()), Times.Never);
    }

    #endregion

    #region RemoveUser Tests

    [Fact]
    public async Task RemoveUser_Success_RemovesMembershipAndRevokesTokens()
    {
        _mockWorkspaceUserRepository
            .Setup(r => r.DeleteWithAdminCheckAsync(OtherUserId, TestWorkspaceId))
            .ReturnsAsync(AdminCheckResult.Success);
        _mockWorkspaceUserRepository
            .Setup(r => r.CountUserMembershipsAsync(OtherUserId))
            .ReturnsAsync(1);

        var result = await _controller.RemoveUser(OtherUserId);

        Assert.IsType<NoContentResult>(result);
        _mockTokenRevocationService.Verify(s => s.RevokeAsync(OtherUserId), Times.Once);
        _mockUserRepository.Verify(r => r.DeleteAsync(It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task RemoveUser_LastMembership_RevokesTokensBeforeDeletingUser()
    {
        _mockWorkspaceUserRepository
            .Setup(r => r.DeleteWithAdminCheckAsync(OtherUserId, TestWorkspaceId))
            .ReturnsAsync(AdminCheckResult.Success);
        _mockWorkspaceUserRepository
            .Setup(r => r.CountUserMembershipsAsync(OtherUserId))
            .ReturnsAsync(0);

        var callOrder = new List<string>();
        _mockTokenRevocationService.Setup(s => s.RevokeAsync(OtherUserId))
            .Callback(() => callOrder.Add("revoke"))
            .Returns(Task.CompletedTask);
        _mockUserRepository.Setup(r => r.DeleteAsync(OtherUserId))
            .Callback(() => callOrder.Add("delete"))
            .ReturnsAsync(true);

        var result = await _controller.RemoveUser(OtherUserId);

        Assert.IsType<NoContentResult>(result);
        // The revocation row has an FK to Users, so it must be written before the hard delete
        Assert.Equal(new[] { "revoke", "delete" }, callOrder);
    }

    [Fact]
    public async Task RemoveUser_Self_ReturnsBadRequestWithoutRevoking()
    {
        var result = await _controller.RemoveUser(TestUserId);

        Assert.IsType<BadRequestObjectResult>(result);
        _mockTokenRevocationService.Verify(s => s.RevokeAsync(It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task RemoveUser_UserNotFound_ReturnsNotFoundWithoutRevoking()
    {
        _mockWorkspaceUserRepository
            .Setup(r => r.DeleteWithAdminCheckAsync(OtherUserId, TestWorkspaceId))
            .ReturnsAsync(AdminCheckResult.UserNotFound);

        var result = await _controller.RemoveUser(OtherUserId);

        Assert.IsType<NotFoundObjectResult>(result);
        _mockTokenRevocationService.Verify(s => s.RevokeAsync(It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task RemoveUser_WouldRemoveLastAdmin_ReturnsBadRequestWithoutRevoking()
    {
        _mockWorkspaceUserRepository
            .Setup(r => r.DeleteWithAdminCheckAsync(OtherUserId, TestWorkspaceId))
            .ReturnsAsync(AdminCheckResult.WouldRemoveLastAdmin);

        var result = await _controller.RemoveUser(OtherUserId);

        Assert.IsType<BadRequestObjectResult>(result);
        _mockTokenRevocationService.Verify(s => s.RevokeAsync(It.IsAny<int>()), Times.Never);
    }

    #endregion
}
