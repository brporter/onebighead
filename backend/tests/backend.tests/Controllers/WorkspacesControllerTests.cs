using OneBigHead.Server.Controllers;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Workspaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Security.Claims;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class WorkspacesControllerTests
{
    private readonly Mock<IWorkspaceRepository> _mockWorkspaceRepository;
    private readonly Mock<IWorkspaceUserRepository> _mockWorkspaceUserRepository;
    private readonly Mock<IWorkspaceSummaryService> _mockWorkspaceSummary = new();
    private readonly WorkspacesController _controller;
    private const int TestWorkspaceId = 1;
    private const int TestUserId = 1;

    public WorkspacesControllerTests()
    {
        _mockWorkspaceRepository = new Mock<IWorkspaceRepository>();
        _mockWorkspaceUserRepository = new Mock<IWorkspaceUserRepository>();

        _controller = new WorkspacesController(
            _mockWorkspaceRepository.Object,
            _mockWorkspaceUserRepository.Object,
            _mockWorkspaceSummary.Object);

        var claims = new List<Claim>
        {
            new("workspace_id", TestWorkspaceId.ToString()),
            new("sub", TestUserId.ToString()),
            new(ClaimTypes.NameIdentifier, TestUserId.ToString()),
            new(ClaimTypes.Email, "test@example.com")
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var claimsPrincipal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = claimsPrincipal }
        };
    }

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(true, false, false)]
    [InlineData(true, true, false)]
    [InlineData(true, true, true)]
    public async Task WorkspaceStats_RequiresAdminMembershipAndAnAvailableSummary(bool member, bool admin, bool found)
    {
        _mockWorkspaceUserRepository.Setup(r => r.GetMembershipAsync(TestUserId, TestWorkspaceId)).ReturnsAsync(member
            ? new WorkspaceUser { UserId = TestUserId, WorkspaceId = TestWorkspaceId, WorkspaceRole = admin ? WorkspaceRole.WorkspaceAdmin : WorkspaceRole.Normal }
            : null);
        var summary = found ? new WorkspaceStatsResponse { WorkspaceId = TestWorkspaceId, ItemCount = 4 } : null;
        _mockWorkspaceSummary.Setup(s => s.GetWorkspaceStatsAsync(TestWorkspaceId)).ReturnsAsync(summary);
        var result = await _controller.GetWorkspaceStats(TestWorkspaceId);
        if (!member || (admin && !found)) Assert.IsType<NotFoundObjectResult>(result);
        else if (!admin) Assert.IsType<ForbidResult>(result);
        else Assert.Same(summary, Assert.IsType<OkObjectResult>(result).Value);
        _mockWorkspaceSummary.Verify(s => s.GetWorkspaceStatsAsync(TestWorkspaceId), member && admin ? Times.Once : Times.Never);
    }

    [Fact]
    public async Task GetWorkspaces_ReturnsOnlyAvailableMembershipsWithTheirCurrentRoles()
    {
        _mockWorkspaceUserRepository.Setup(r => r.GetByUserIdAsync(TestUserId)).ReturnsAsync([
            new WorkspaceUser { WorkspaceId = 2, WorkspaceRole = WorkspaceRole.Normal,
                Workspace = new Workspace { Id = 2, Name = "Shared", HasCompletedWelcome = true } },
            new WorkspaceUser { WorkspaceId = 3, WorkspaceRole = WorkspaceRole.WorkspaceAdmin,
                Workspace = new Workspace { Id = 3, Name = "New" } },
            new WorkspaceUser { WorkspaceId = 4, Workspace = new Workspace { Id = 4, IsDeleted = true } },
            new WorkspaceUser { WorkspaceId = 5, Workspace = null! }
        ]);

        var response = Assert.IsType<List<WorkspaceMembershipResponse>>(
            Assert.IsType<OkObjectResult>(await _controller.GetWorkspaces()).Value);

        Assert.Collection(response,
            member =>
            {
                Assert.Equal(2, member.WorkspaceId);
                Assert.Equal("Shared", member.WorkspaceName);
                Assert.Equal(WorkspaceRole.Normal, member.WorkspaceRole);
                Assert.True(member.HasCompletedWelcome);
            },
            member =>
            {
                Assert.Equal(3, member.WorkspaceId);
                Assert.Equal("New", member.WorkspaceName);
                Assert.Equal(WorkspaceRole.WorkspaceAdmin, member.WorkspaceRole);
                Assert.False(member.HasCompletedWelcome);
            });
        _mockWorkspaceUserRepository.Verify(r => r.GetByUserIdAsync(TestUserId), Times.Once);
    }

    [Fact]
    public async Task GetWorkspaces_ReturnsAnEmptyListWhenThereAreNoMemberships()
    {
        _mockWorkspaceUserRepository.Setup(r => r.GetByUserIdAsync(TestUserId)).ReturnsAsync([]);
        Assert.Empty(Assert.IsType<List<WorkspaceMembershipResponse>>(
            Assert.IsType<OkObjectResult>(await _controller.GetWorkspaces()).Value));
    }

}
