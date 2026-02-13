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

    #region CreateAsync Tests

    [Fact]
    public async Task CreateAsync_CreatesNewMembership()
    {
        // Arrange
        var repo = GetRepository();

        // Create a new user first
        await Factory.SeedDatabaseAsync(context =>
        {
            context.Users.Add(new User
            {
                Id = 500,
                ActiveWorkspaceId = DefaultWorkspaceId,
                Email = "newuser@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "new-user-500"
            });
        });

        // Act
        var result = await repo.CreateAsync(500, DefaultWorkspaceId, WorkspaceRole.Normal);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(500, result.UserId);
        Assert.Equal(DefaultWorkspaceId, result.WorkspaceId);
        Assert.Equal(WorkspaceRole.Normal, result.WorkspaceRole);
        Assert.NotNull(result.Workspace);
        Assert.NotNull(result.User);
    }

    #endregion

    #region UpdateRoleAsync Tests

    [Fact]
    public async Task UpdateRoleAsync_UpdatesRole_WhenMembershipExists()
    {
        // Arrange
        var repo = GetRepository();

        // Create a test user
        await Factory.SeedDatabaseAsync(context =>
        {
            context.Users.Add(new User
            {
                Id = 501,
                ActiveWorkspaceId = DefaultWorkspaceId,
                Email = "roletest@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "role-test-501"
            });
            context.WorkspaceUsers.Add(new WorkspaceUser
            {
                UserId = 501,
                WorkspaceId = DefaultWorkspaceId,
                WorkspaceRole = WorkspaceRole.Normal
            });
        });

        // Act
        var result = await repo.UpdateRoleAsync(501, DefaultWorkspaceId, WorkspaceRole.WorkspaceAdmin);

        // Assert
        Assert.True(result);

        // Verify the change
        var updated = await repo.GetMembershipAsync(501, DefaultWorkspaceId);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, updated?.WorkspaceRole);
    }

    [Fact]
    public async Task UpdateRoleAsync_ReturnsFalse_WhenMembershipNotExists()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var result = await repo.UpdateRoleAsync(9999, DefaultWorkspaceId, WorkspaceRole.Normal);

        // Assert
        Assert.False(result);
    }

    #endregion

    #region DeleteAsync Tests

    [Fact]
    public async Task DeleteAsync_DeletesMembership_WhenExists()
    {
        // Arrange
        var repo = GetRepository();

        // Create a test user
        await Factory.SeedDatabaseAsync(context =>
        {
            context.Users.Add(new User
            {
                Id = 502,
                ActiveWorkspaceId = DefaultWorkspaceId,
                Email = "deletetest@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "delete-test-502"
            });
            context.WorkspaceUsers.Add(new WorkspaceUser
            {
                UserId = 502,
                WorkspaceId = DefaultWorkspaceId,
                WorkspaceRole = WorkspaceRole.Normal
            });
        });

        // Act
        var result = await repo.DeleteAsync(502, DefaultWorkspaceId);

        // Assert
        Assert.True(result);

        // Verify deletion
        var deleted = await repo.GetMembershipAsync(502, DefaultWorkspaceId);
        Assert.Null(deleted);
    }

    [Fact]
    public async Task DeleteAsync_ReturnsFalse_WhenNotExists()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var result = await repo.DeleteAsync(9999, DefaultWorkspaceId);

        // Assert
        Assert.False(result);
    }

    #endregion

    #region CountAdminsInWorkspaceAsync Tests

    [Fact]
    public async Task CountAdminsInWorkspaceAsync_ReturnsCorrectCount()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var count = await repo.CountAdminsInWorkspaceAsync(DefaultWorkspaceId);

        // Assert - Default user is WorkspaceAdmin
        Assert.True(count >= 1);
    }

    #endregion

    #region CountMembersInWorkspaceAsync Tests

    [Fact]
    public async Task CountMembersInWorkspaceAsync_ReturnsCorrectCount()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var count = await repo.CountMembersInWorkspaceAsync(DefaultWorkspaceId);

        // Assert
        Assert.True(count >= 1);
    }

    #endregion

    #region CountUserMembershipsAsync Tests

    [Fact]
    public async Task CountUserMembershipsAsync_ReturnsCorrectCount()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var count = await repo.CountUserMembershipsAsync(DefaultUserId);

        // Assert
        Assert.True(count >= 1);
    }

    #endregion

    #region UpdateRoleWithAdminCheckAsync Tests

    [Fact]
    public async Task UpdateRoleWithAdminCheckAsync_UpdatesRole_WhenNotLastAdmin()
    {
        // Arrange
        var repo = GetRepository();

        // Create a second admin and a user to demote
        await Factory.SeedDatabaseAsync(context =>
        {
            // Second admin
            context.Users.Add(new User
            {
                Id = 600,
                ActiveWorkspaceId = DefaultWorkspaceId,
                Email = "admin2@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "admin-2-600"
            });
            context.WorkspaceUsers.Add(new WorkspaceUser
            {
                UserId = 600,
                WorkspaceId = DefaultWorkspaceId,
                WorkspaceRole = WorkspaceRole.WorkspaceAdmin
            });

            // Admin to demote
            context.Users.Add(new User
            {
                Id = 601,
                ActiveWorkspaceId = DefaultWorkspaceId,
                Email = "demote@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "demote-601"
            });
            context.WorkspaceUsers.Add(new WorkspaceUser
            {
                UserId = 601,
                WorkspaceId = DefaultWorkspaceId,
                WorkspaceRole = WorkspaceRole.WorkspaceAdmin
            });
        });

        // Act
        var result = await repo.UpdateRoleWithAdminCheckAsync(601, DefaultWorkspaceId, WorkspaceRole.Normal);

        // Assert
        Assert.Equal(AdminCheckResult.Success, result);

        // Verify role was changed
        var updated = await repo.GetMembershipAsync(601, DefaultWorkspaceId);
        Assert.Equal(WorkspaceRole.Normal, updated?.WorkspaceRole);
    }

    [Fact]
    public async Task UpdateRoleWithAdminCheckAsync_ReturnsWouldRemoveLastAdmin_WhenDemotingLastAdmin()
    {
        // Arrange
        var repo = GetRepository();

        // Create a new workspace with only one admin
        await Factory.SeedDatabaseAsync(context =>
        {
            context.Workspaces.Add(new Workspace { Id = 100, Name = "Single Admin Workspace" });
            context.Users.Add(new User
            {
                Id = 700,
                ActiveWorkspaceId = 100,
                Email = "singleadmin@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "single-admin-700"
            });
            context.WorkspaceUsers.Add(new WorkspaceUser
            {
                UserId = 700,
                WorkspaceId = 100,
                WorkspaceRole = WorkspaceRole.WorkspaceAdmin
            });
        });

        // Act
        var result = await repo.UpdateRoleWithAdminCheckAsync(700, 100, WorkspaceRole.Normal);

        // Assert
        Assert.Equal(AdminCheckResult.WouldRemoveLastAdmin, result);

        // Verify role was NOT changed
        var unchanged = await repo.GetMembershipAsync(700, 100);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, unchanged?.WorkspaceRole);
    }

    [Fact]
    public async Task UpdateRoleWithAdminCheckAsync_ReturnsUserNotFound_WhenUserDoesNotExist()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var result = await repo.UpdateRoleWithAdminCheckAsync(9999, DefaultWorkspaceId, WorkspaceRole.Normal);

        // Assert
        Assert.Equal(AdminCheckResult.UserNotFound, result);
    }

    [Fact]
    public async Task UpdateRoleWithAdminCheckAsync_AllowsPromotionToAdmin()
    {
        // Arrange
        var repo = GetRepository();

        // Create a normal user
        await Factory.SeedDatabaseAsync(context =>
        {
            context.Users.Add(new User
            {
                Id = 701,
                ActiveWorkspaceId = DefaultWorkspaceId,
                Email = "promote@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "promote-701"
            });
            context.WorkspaceUsers.Add(new WorkspaceUser
            {
                UserId = 701,
                WorkspaceId = DefaultWorkspaceId,
                WorkspaceRole = WorkspaceRole.Normal
            });
        });

        // Act
        var result = await repo.UpdateRoleWithAdminCheckAsync(701, DefaultWorkspaceId, WorkspaceRole.WorkspaceAdmin);

        // Assert
        Assert.Equal(AdminCheckResult.Success, result);

        // Verify role was changed
        var updated = await repo.GetMembershipAsync(701, DefaultWorkspaceId);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, updated?.WorkspaceRole);
    }

    [Fact]
    public async Task UpdateRoleWithAdminCheckAsync_AllowsSameRoleUpdate()
    {
        // Arrange
        var repo = GetRepository();

        // Act - update to same role
        var result = await repo.UpdateRoleWithAdminCheckAsync(DefaultUserId, DefaultWorkspaceId, WorkspaceRole.WorkspaceAdmin);

        // Assert
        Assert.Equal(AdminCheckResult.Success, result);
    }

    #endregion

    #region DeleteWithAdminCheckAsync Tests

    [Fact]
    public async Task DeleteWithAdminCheckAsync_DeletesUser_WhenNotLastAdmin()
    {
        // Arrange
        var repo = GetRepository();

        // Create an admin to delete (there's already one from default setup)
        await Factory.SeedDatabaseAsync(context =>
        {
            context.Users.Add(new User
            {
                Id = 800,
                ActiveWorkspaceId = DefaultWorkspaceId,
                Email = "deleteadmin@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "delete-admin-800"
            });
            context.WorkspaceUsers.Add(new WorkspaceUser
            {
                UserId = 800,
                WorkspaceId = DefaultWorkspaceId,
                WorkspaceRole = WorkspaceRole.WorkspaceAdmin
            });
        });

        // Act
        var result = await repo.DeleteWithAdminCheckAsync(800, DefaultWorkspaceId);

        // Assert
        Assert.Equal(AdminCheckResult.Success, result);

        // Verify deletion
        var deleted = await repo.GetMembershipAsync(800, DefaultWorkspaceId);
        Assert.Null(deleted);
    }

    [Fact]
    public async Task DeleteWithAdminCheckAsync_ReturnsWouldRemoveLastAdmin_WhenDeletingLastAdmin()
    {
        // Arrange
        var repo = GetRepository();

        // Create a new workspace with only one admin
        await Factory.SeedDatabaseAsync(context =>
        {
            context.Workspaces.Add(new Workspace { Id = 101, Name = "Delete Test Workspace" });
            context.Users.Add(new User
            {
                Id = 801,
                ActiveWorkspaceId = 101,
                Email = "lastadmin@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "last-admin-801"
            });
            context.WorkspaceUsers.Add(new WorkspaceUser
            {
                UserId = 801,
                WorkspaceId = 101,
                WorkspaceRole = WorkspaceRole.WorkspaceAdmin
            });
        });

        // Act
        var result = await repo.DeleteWithAdminCheckAsync(801, 101);

        // Assert
        Assert.Equal(AdminCheckResult.WouldRemoveLastAdmin, result);

        // Verify NOT deleted
        var notDeleted = await repo.GetMembershipAsync(801, 101);
        Assert.NotNull(notDeleted);
    }

    [Fact]
    public async Task DeleteWithAdminCheckAsync_ReturnsUserNotFound_WhenUserDoesNotExist()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var result = await repo.DeleteWithAdminCheckAsync(9999, DefaultWorkspaceId);

        // Assert
        Assert.Equal(AdminCheckResult.UserNotFound, result);
    }

    [Fact]
    public async Task DeleteWithAdminCheckAsync_DeletesNormalUser()
    {
        // Arrange
        var repo = GetRepository();

        // Create a normal user
        await Factory.SeedDatabaseAsync(context =>
        {
            context.Users.Add(new User
            {
                Id = 802,
                ActiveWorkspaceId = DefaultWorkspaceId,
                Email = "normaldelete@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "normal-delete-802"
            });
            context.WorkspaceUsers.Add(new WorkspaceUser
            {
                UserId = 802,
                WorkspaceId = DefaultWorkspaceId,
                WorkspaceRole = WorkspaceRole.Normal
            });
        });

        // Act
        var result = await repo.DeleteWithAdminCheckAsync(802, DefaultWorkspaceId);

        // Assert
        Assert.Equal(AdminCheckResult.Success, result);

        // Verify deletion
        var deleted = await repo.GetMembershipAsync(802, DefaultWorkspaceId);
        Assert.Null(deleted);
    }

    #endregion
}
