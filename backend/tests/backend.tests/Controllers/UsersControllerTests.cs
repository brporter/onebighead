using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class UsersControllerTests
{
    [Fact]
    public async Task RestorableWorkspaces_ReturnsDeletedAdminWorkspacesAndTheirStatistics()
    {
        var deletedAt = DateTime.UtcNow.AddDays(-5).AddHours(1);
        var memberships = new Mock<IWorkspaceUserRepository>(MockBehavior.Strict);
        var workspaces = new Mock<IWorkspaceRepository>(MockBehavior.Strict);
        memberships.Setup(m => m.GetAdminMembershipsIncludingDeletedAsync(7)).ReturnsAsync([
            new WorkspaceUser { WorkspaceId = 1, Workspace = null! },
            new WorkspaceUser { WorkspaceId = 2, Workspace = new Workspace { Id = 2 } },
            new WorkspaceUser { WorkspaceId = 3, Workspace = new Workspace { Id = 3, Name = "Recoverable", IsDeleted = true, DeletedAt = deletedAt } },
            new WorkspaceUser { WorkspaceId = 4, Workspace = new Workspace { Id = 4, Name = "Expired", IsDeleted = true, DeletedAt = deletedAt.AddDays(-40) } }
        ]);
        workspaces.Setup(w => w.GetStatsAsync(3)).ReturnsAsync(new WorkspaceStats { CollectionCount = 2, ItemCount = 3, CategoryCount = 4, ImageCount = 5 });
        workspaces.Setup(w => w.GetStatsAsync(4)).ReturnsAsync(new WorkspaceStats());
        var controller = Controller(memberships.Object, workspaces.Object);

        var result = Assert.IsType<OkObjectResult>(await controller.GetRestorableWorkspaces());
        var rows = Assert.IsType<List<RestorableWorkspaceResponse>>(result.Value);
        Assert.Equal(new[] { 3, 4 }, rows.Select(w => w.WorkspaceId));
        Assert.Equal("Recoverable", rows[0].Name);
        Assert.Equal(deletedAt, rows[0].DeletedAt);
        Assert.Equal(26, rows[0].DaysRemaining);
        Assert.Equal(2, rows[0].Stats.CollectionCount);
        Assert.Equal(3, rows[0].Stats.ItemCount);
        Assert.Equal(4, rows[0].Stats.CategoryCount);
        Assert.Equal(5, rows[0].Stats.ImageCount);
        Assert.Equal(0, rows[1].DaysRemaining);
        memberships.Verify(m => m.GetAdminMembershipsIncludingDeletedAsync(7), Times.Once);
        workspaces.Verify(w => w.GetStatsAsync(3), Times.Once);
        workspaces.Verify(w => w.GetStatsAsync(4), Times.Once);
        workspaces.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task RestorableWorkspaces_WithoutAdminMemberships_ReturnsEmptyList()
    {
        var memberships = new Mock<IWorkspaceUserRepository>(MockBehavior.Strict);
        var workspaces = new Mock<IWorkspaceRepository>(MockBehavior.Strict);
        memberships.Setup(m => m.GetAdminMembershipsIncludingDeletedAsync(7)).ReturnsAsync([]);
        var response = await Controller(memberships.Object, workspaces.Object).GetRestorableWorkspaces();
        Assert.Empty(Assert.IsType<List<RestorableWorkspaceResponse>>(Assert.IsType<OkObjectResult>(response).Value));
        workspaces.VerifyNoOtherCalls();
    }

    private static UsersController Controller(IWorkspaceUserRepository memberships, IWorkspaceRepository workspaces) => new(memberships, workspaces)
    {
        ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "7")], "Test"))
            }
        }
    };
}
