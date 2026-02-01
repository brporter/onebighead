using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace OneBigHead.Server.Tests.Integration.Data;

[Trait("Category", "Integration")]
public class TenantUserRepositoryTests : IntegrationTestBase
{
    public TenantUserRepositoryTests(CustomWebApplicationFactory factory)
        : base(factory)
    {
    }

    private ITenantUserRepository GetRepository()
    {
        var scope = Factory.Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<ITenantUserRepository>();
    }

    #region GetMembershipAsync Tests

    [Fact]
    public async Task GetMembershipAsync_ReturnsMembership_WhenExists()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var result = await repo.GetMembershipAsync(DefaultUserId, DefaultTenantId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(DefaultUserId, result.UserId);
        Assert.Equal(DefaultTenantId, result.TenantId);
        Assert.NotNull(result.Tenant);
        Assert.NotNull(result.User);
    }

    [Fact]
    public async Task GetMembershipAsync_ReturnsNull_WhenNotExists()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var result = await repo.GetMembershipAsync(9999, DefaultTenantId);

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
        Assert.All(result, tu => Assert.NotNull(tu.Tenant));
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

    #region GetByTenantIdAsync Tests

    [Fact]
    public async Task GetByTenantIdAsync_ReturnsMemberships_ForTenant()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var result = await repo.GetByTenantIdAsync(DefaultTenantId);

        // Assert
        Assert.NotEmpty(result);
        Assert.All(result, tu => Assert.Equal(DefaultTenantId, tu.TenantId));
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
                ActiveTenantId = DefaultTenantId,
                Email = "newuser@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "new-user-500"
            });
        });

        // Act
        var result = await repo.CreateAsync(500, DefaultTenantId, TenantRole.Normal);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(500, result.UserId);
        Assert.Equal(DefaultTenantId, result.TenantId);
        Assert.Equal(TenantRole.Normal, result.TenantRole);
        Assert.NotNull(result.Tenant);
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
                ActiveTenantId = DefaultTenantId,
                Email = "roletest@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "role-test-501"
            });
            context.TenantUsers.Add(new TenantUser
            {
                UserId = 501,
                TenantId = DefaultTenantId,
                TenantRole = TenantRole.Normal
            });
        });

        // Act
        var result = await repo.UpdateRoleAsync(501, DefaultTenantId, TenantRole.TenantAdmin);

        // Assert
        Assert.True(result);

        // Verify the change
        var updated = await repo.GetMembershipAsync(501, DefaultTenantId);
        Assert.Equal(TenantRole.TenantAdmin, updated?.TenantRole);
    }

    [Fact]
    public async Task UpdateRoleAsync_ReturnsFalse_WhenMembershipNotExists()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var result = await repo.UpdateRoleAsync(9999, DefaultTenantId, TenantRole.Normal);

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
                ActiveTenantId = DefaultTenantId,
                Email = "deletetest@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "delete-test-502"
            });
            context.TenantUsers.Add(new TenantUser
            {
                UserId = 502,
                TenantId = DefaultTenantId,
                TenantRole = TenantRole.Normal
            });
        });

        // Act
        var result = await repo.DeleteAsync(502, DefaultTenantId);

        // Assert
        Assert.True(result);

        // Verify deletion
        var deleted = await repo.GetMembershipAsync(502, DefaultTenantId);
        Assert.Null(deleted);
    }

    [Fact]
    public async Task DeleteAsync_ReturnsFalse_WhenNotExists()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var result = await repo.DeleteAsync(9999, DefaultTenantId);

        // Assert
        Assert.False(result);
    }

    #endregion

    #region CountAdminsInTenantAsync Tests

    [Fact]
    public async Task CountAdminsInTenantAsync_ReturnsCorrectCount()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var count = await repo.CountAdminsInTenantAsync(DefaultTenantId);

        // Assert - Default user is TenantAdmin
        Assert.True(count >= 1);
    }

    #endregion

    #region CountMembersInTenantAsync Tests

    [Fact]
    public async Task CountMembersInTenantAsync_ReturnsCorrectCount()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var count = await repo.CountMembersInTenantAsync(DefaultTenantId);

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
                ActiveTenantId = DefaultTenantId,
                Email = "admin2@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "admin-2-600"
            });
            context.TenantUsers.Add(new TenantUser
            {
                UserId = 600,
                TenantId = DefaultTenantId,
                TenantRole = TenantRole.TenantAdmin
            });

            // Admin to demote
            context.Users.Add(new User
            {
                Id = 601,
                ActiveTenantId = DefaultTenantId,
                Email = "demote@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "demote-601"
            });
            context.TenantUsers.Add(new TenantUser
            {
                UserId = 601,
                TenantId = DefaultTenantId,
                TenantRole = TenantRole.TenantAdmin
            });
        });

        // Act
        var result = await repo.UpdateRoleWithAdminCheckAsync(601, DefaultTenantId, TenantRole.Normal);

        // Assert
        Assert.Equal(AdminCheckResult.Success, result);

        // Verify role was changed
        var updated = await repo.GetMembershipAsync(601, DefaultTenantId);
        Assert.Equal(TenantRole.Normal, updated?.TenantRole);
    }

    [Fact]
    public async Task UpdateRoleWithAdminCheckAsync_ReturnsWouldRemoveLastAdmin_WhenDemotingLastAdmin()
    {
        // Arrange
        var repo = GetRepository();

        // Create a new tenant with only one admin
        await Factory.SeedDatabaseAsync(context =>
        {
            context.Tenants.Add(new Tenant { Id = 100, Name = "Single Admin Tenant" });
            context.Users.Add(new User
            {
                Id = 700,
                ActiveTenantId = 100,
                Email = "singleadmin@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "single-admin-700"
            });
            context.TenantUsers.Add(new TenantUser
            {
                UserId = 700,
                TenantId = 100,
                TenantRole = TenantRole.TenantAdmin
            });
        });

        // Act
        var result = await repo.UpdateRoleWithAdminCheckAsync(700, 100, TenantRole.Normal);

        // Assert
        Assert.Equal(AdminCheckResult.WouldRemoveLastAdmin, result);

        // Verify role was NOT changed
        var unchanged = await repo.GetMembershipAsync(700, 100);
        Assert.Equal(TenantRole.TenantAdmin, unchanged?.TenantRole);
    }

    [Fact]
    public async Task UpdateRoleWithAdminCheckAsync_ReturnsUserNotFound_WhenUserDoesNotExist()
    {
        // Arrange
        var repo = GetRepository();

        // Act
        var result = await repo.UpdateRoleWithAdminCheckAsync(9999, DefaultTenantId, TenantRole.Normal);

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
                ActiveTenantId = DefaultTenantId,
                Email = "promote@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "promote-701"
            });
            context.TenantUsers.Add(new TenantUser
            {
                UserId = 701,
                TenantId = DefaultTenantId,
                TenantRole = TenantRole.Normal
            });
        });

        // Act
        var result = await repo.UpdateRoleWithAdminCheckAsync(701, DefaultTenantId, TenantRole.TenantAdmin);

        // Assert
        Assert.Equal(AdminCheckResult.Success, result);

        // Verify role was changed
        var updated = await repo.GetMembershipAsync(701, DefaultTenantId);
        Assert.Equal(TenantRole.TenantAdmin, updated?.TenantRole);
    }

    [Fact]
    public async Task UpdateRoleWithAdminCheckAsync_AllowsSameRoleUpdate()
    {
        // Arrange
        var repo = GetRepository();

        // Act - update to same role
        var result = await repo.UpdateRoleWithAdminCheckAsync(DefaultUserId, DefaultTenantId, TenantRole.TenantAdmin);

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
                ActiveTenantId = DefaultTenantId,
                Email = "deleteadmin@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "delete-admin-800"
            });
            context.TenantUsers.Add(new TenantUser
            {
                UserId = 800,
                TenantId = DefaultTenantId,
                TenantRole = TenantRole.TenantAdmin
            });
        });

        // Act
        var result = await repo.DeleteWithAdminCheckAsync(800, DefaultTenantId);

        // Assert
        Assert.Equal(AdminCheckResult.Success, result);

        // Verify deletion
        var deleted = await repo.GetMembershipAsync(800, DefaultTenantId);
        Assert.Null(deleted);
    }

    [Fact]
    public async Task DeleteWithAdminCheckAsync_ReturnsWouldRemoveLastAdmin_WhenDeletingLastAdmin()
    {
        // Arrange
        var repo = GetRepository();

        // Create a new tenant with only one admin
        await Factory.SeedDatabaseAsync(context =>
        {
            context.Tenants.Add(new Tenant { Id = 101, Name = "Delete Test Tenant" });
            context.Users.Add(new User
            {
                Id = 801,
                ActiveTenantId = 101,
                Email = "lastadmin@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "last-admin-801"
            });
            context.TenantUsers.Add(new TenantUser
            {
                UserId = 801,
                TenantId = 101,
                TenantRole = TenantRole.TenantAdmin
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
        var result = await repo.DeleteWithAdminCheckAsync(9999, DefaultTenantId);

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
                ActiveTenantId = DefaultTenantId,
                Email = "normaldelete@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "normal-delete-802"
            });
            context.TenantUsers.Add(new TenantUser
            {
                UserId = 802,
                TenantId = DefaultTenantId,
                TenantRole = TenantRole.Normal
            });
        });

        // Act
        var result = await repo.DeleteWithAdminCheckAsync(802, DefaultTenantId);

        // Assert
        Assert.Equal(AdminCheckResult.Success, result);

        // Verify deletion
        var deleted = await repo.GetMembershipAsync(802, DefaultTenantId);
        Assert.Null(deleted);
    }

    #endregion
}
