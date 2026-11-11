using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace OneBigHead.Server.Tests.Integration.Data;

[Trait("Category", "Integration")]
public class WorkspaceUserRepositoryTests : IntegrationTestBase
{
    public WorkspaceUserRepositoryTests(CustomWebApplicationFactory factory)
        : base(factory)
    {
    }

    private IWorkspaceUserRepository GetRepository()
    {
        var scope = Factory.Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<IWorkspaceUserRepository>();
    }

    #region GetMembershipAsync Tests

    [Fact]
    public async Task GetMembershipAsync_ReturnsMembership_WhenExists()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var result = await repo.GetMembershipAsync(DefaultUserId, DefaultWorkspaceId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(DefaultUserId, result.UserId);
        Assert.Equal(DefaultWorkspaceId, result.WorkspaceId);
        Assert.NotNull(result.Workspace);
        Assert.NotNull(result.User);
    }

    [Fact]
    public async Task GetMembershipAsync_ReturnsNull_WhenNotExists()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var result = await repo.GetMembershipAsync(9999, DefaultWorkspaceId);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region GetByUserIdAsync Tests

    [Fact]
    public async Task GetByUserIdAsync_ReturnsMemberships_ForUser()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var result = await repo.GetByUserIdAsync(DefaultUserId);

        // Assert
        Assert.NotEmpty(result);
        Assert.All(result, tu => Assert.Equal(DefaultUserId, tu.UserId));
        Assert.All(result, tu => Assert.NotNull(tu.Workspace));
    }

    [Fact]
    public async Task GetByUserIdAsync_ReturnsEmpty_WhenNoMemberships()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var result = await repo.GetByUserIdAsync(9999);

        // Assert
        Assert.Empty(result);
    }

    #endregion

    #region GetByWorkspaceIdAsync Tests

    [Fact]
    public async Task GetByWorkspaceIdAsync_ReturnsMemberships_ForWorkspace()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var result = await repo.GetByWorkspaceIdAsync(DefaultWorkspaceId);

        // Assert
        Assert.NotEmpty(result);
        Assert.All(result, tu => Assert.Equal(DefaultWorkspaceId, tu.WorkspaceId));
        Assert.All(result, tu => Assert.NotNull(tu.User));
    }

    #endregion


}
