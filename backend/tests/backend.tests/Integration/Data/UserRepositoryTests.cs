using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace OneBigHead.Server.Tests.Integration.Data;

[Trait("Category", "Integration")]
public class UserRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly UserRepository _repository;
    private readonly WorkspaceUserRepository _workspaceUserRepository;

    public UserRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning))
            .Options;

        _context = new AppDbContext(options);
        var contextFactory = new TestDbContextFactory(options);
        _repository = new UserRepository(contextFactory);
        _workspaceUserRepository = new WorkspaceUserRepository(contextFactory);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    private async Task<Workspace> CreateTestWorkspaceAsync()
    {
        var workspace = new Workspace
        {
            Name = "test.example.com",
            CreatedAt = DateTime.UtcNow
        };
        _context.Workspaces.Add(workspace);
        await _context.SaveChangesAsync();
        return workspace;
    }

    private async Task<User> CreateTestUserAsync(Workspace workspace, string email, WorkspaceRole role = WorkspaceRole.Normal)
    {
        var user = new User
        {
            ActiveWorkspaceId = workspace.Id,
            Email = email,
            IdentityProvider = IdentityProvider.Microsoft,
            ProviderSubjectId = $"ms-{email}"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        var workspaceUser = new WorkspaceUser
        {
            UserId = user.Id,
            WorkspaceId = workspace.Id,
            WorkspaceRole = role
        };
        _context.WorkspaceUsers.Add(workspaceUser);
        await _context.SaveChangesAsync();

        return user;
    }

    #region GetByEmailAsync Tests

    [Fact]
    public async Task GetByEmailAsync_ReturnsUser_WhenExists()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync();
        var user = await CreateTestUserAsync(workspace, "test@example.com");

        // Act
        var result = await _repository.GetByEmailAsync("test@example.com");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("test@example.com", result.Email);
        Assert.NotNull(result.ActiveWorkspace);
    }

    [Fact]
    public async Task GetByEmailAsync_ReturnsNull_WhenNotExists()
    {
        // Act
        var result = await _repository.GetByEmailAsync("nonexistent@example.com");

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region GetByProviderIdAsync Tests

    [Fact]
    public async Task GetByProviderIdAsync_ReturnsUser_WhenExists()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync();
        var user = new User
        {
            ActiveWorkspaceId = workspace.Id,
            Email = "test@example.com",
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "google-sub-123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByProviderIdAsync(IdentityProvider.Google, "google-sub-123");

        // Assert
        Assert.NotNull(result);
        Assert.Equal(IdentityProvider.Google, result.IdentityProvider);
        Assert.Equal("google-sub-123", result.ProviderSubjectId);
    }

    [Fact]
    public async Task GetByProviderIdAsync_ReturnsNull_WhenProviderMismatch()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync();
        var user = new User
        {
            ActiveWorkspaceId = workspace.Id,
            Email = "test@example.com",
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "google-sub-123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Act - same subject ID but different provider
        var result = await _repository.GetByProviderIdAsync(IdentityProvider.Microsoft, "google-sub-123");

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region GetByIdAsync Tests

    [Fact]
    public async Task GetByIdAsync_ReturnsUser_WhenExists()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync();
        var user = await CreateTestUserAsync(workspace, "test@example.com");

        // Act
        var result = await _repository.GetByIdAsync(user.Id);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(user.Id, result.Id);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenNotExists()
    {
        // Act
        var result = await _repository.GetByIdAsync(999);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region CreateWithNewWorkspaceAsync Tests

    [Fact]
    public async Task CreateWithNewWorkspaceAsync_CreatesUserAndWorkspace()
    {
        // Act
        var result = await _repository.CreateWithNewWorkspaceAsync(
            "newuser@example.com",
            IdentityProvider.Microsoft,
            "ms-new-user-123");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("newuser@example.com", result.Email);
        Assert.Equal(IdentityProvider.Microsoft, result.IdentityProvider);
        Assert.NotNull(result.ActiveWorkspace);
        Assert.Equal("example.com", result.ActiveWorkspace.Name);
    }

    [Fact]
    public async Task CreateWithNewWorkspaceAsync_UsesDomainAsWorkspaceName()
    {
        // Act
        var result = await _repository.CreateWithNewWorkspaceAsync(
            "john@contoso.com",
            IdentityProvider.Google,
            "google-123");

        // Assert
        Assert.NotNull(result.ActiveWorkspace);
        Assert.Equal("contoso.com", result.ActiveWorkspace.Name);
    }

    [Fact]
    public async Task CreateWithNewWorkspaceAsync_SavesUserToDatabase()
    {
        // Act
        var result = await _repository.CreateWithNewWorkspaceAsync(
            "test@domain.com",
            IdentityProvider.Apple,
            "apple-456");

        // Assert
        var savedUser = await _context.Users.FindAsync(result.Id);
        Assert.NotNull(savedUser);
        Assert.Equal("test@domain.com", savedUser.Email);
    }

    [Fact]
    public async Task CreateWithNewWorkspaceAsync_SavesWorkspaceToDatabase()
    {
        // Act
        var result = await _repository.CreateWithNewWorkspaceAsync(
            "user@newdomain.com",
            IdentityProvider.Microsoft,
            "ms-789");

        // Assert
        var savedWorkspace = await _context.Workspaces.FindAsync(result.ActiveWorkspaceId);
        Assert.NotNull(savedWorkspace);
        Assert.Equal("newdomain.com", savedWorkspace.Name);
    }

    [Fact]
    public async Task CreateWithNewWorkspaceAsync_DoesNotCreateDefaultCollection()
    {
        // New behavior: collections are created through setup wizard, not auto-created
        // Act
        var result = await _repository.CreateWithNewWorkspaceAsync(
            "user@test.com",
            IdentityProvider.Microsoft,
            "ms-collection-test");

        // Assert - no collections should be created
        var collections = await _context.Collections
            .Where(c => c.WorkspaceId == result.ActiveWorkspaceId)
            .ToListAsync();

        Assert.Empty(collections);
    }

    [Fact]
    public async Task CreateWithNewWorkspaceAsync_DoesNotCreateUnassignedCategory()
    {
        // New behavior: unassigned category is created per collection during setup wizard
        // Act
        var result = await _repository.CreateWithNewWorkspaceAsync(
            "user@category-test.com",
            IdentityProvider.Google,
            "google-category-test");

        // Assert - no categories should exist
        var categories = await _context.Categories
            .Where(c => c.WorkspaceId == result.ActiveWorkspaceId)
            .ToListAsync();
        Assert.Empty(categories);
    }

    [Fact]
    public async Task CreateWithNewWorkspaceAsync_UsesWholeEmail_WhenNoAtSign()
    {
        // Act
        var result = await _repository.CreateWithNewWorkspaceAsync(
            "localuser",
            IdentityProvider.Apple,
            "apple-local-test");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("localuser", result.Email);

        var workspace = await _context.Workspaces.FindAsync(result.ActiveWorkspaceId);
        Assert.NotNull(workspace);
        Assert.Equal("localuser", workspace.Name);
    }

    [Fact]
    public async Task CreateWithNewWorkspaceAsync_SetsFirstUserAsWorkspaceAdmin()
    {
        // Act
        var result = await _repository.CreateWithNewWorkspaceAsync(
            "admin@newdomain.com",
            IdentityProvider.Microsoft,
            "ms-first-user");

        // Assert - check WorkspaceUser record for role
        var workspaceUser = await _context.WorkspaceUsers
            .FirstOrDefaultAsync(tu => tu.UserId == result.Id && tu.WorkspaceId == result.ActiveWorkspaceId);
        Assert.NotNull(workspaceUser);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, workspaceUser.WorkspaceRole);
    }

    #endregion

    #region GetByWorkspaceIdAsync Tests

    [Fact]
    public async Task GetByWorkspaceIdAsync_ReturnsAllWorkspaceUsers()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync();
        await CreateTestUserAsync(workspace, "user1@example.com", WorkspaceRole.WorkspaceAdmin);
        await CreateTestUserAsync(workspace, "user2@example.com", WorkspaceRole.Normal);

        // Act
        var result = await _repository.GetByWorkspaceIdAsync(workspace.Id);

        // Assert
        var users = result.ToList();
        Assert.Equal(2, users.Count);
        Assert.Contains(users, u => u.Email == "user1@example.com");
        Assert.Contains(users, u => u.Email == "user2@example.com");
    }

    [Fact]
    public async Task GetByWorkspaceIdAsync_ReturnsEmptyForNonExistentWorkspace()
    {
        // Act
        var result = await _repository.GetByWorkspaceIdAsync(999);

        // Assert
        Assert.Empty(result);
    }

    #endregion

    #region CreatePendingUserAsync Tests

    [Fact]
    public async Task CreatePendingUserAsync_CreatesPendingUser()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync();

        // Act
        var result = await _repository.CreatePendingUserAsync(workspace.Id, "pending@example.com", WorkspaceRole.Normal);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("pending@example.com", result.Email);
        Assert.Equal(IdentityProvider.None, result.IdentityProvider);
        Assert.Null(result.ProviderSubjectId);
        Assert.False(result.IsLinked);

        // Verify WorkspaceUser membership
        var workspaceUser = await _context.WorkspaceUsers
            .FirstOrDefaultAsync(tu => tu.UserId == result.Id && tu.WorkspaceId == workspace.Id);
        Assert.NotNull(workspaceUser);
        Assert.Equal(WorkspaceRole.Normal, workspaceUser.WorkspaceRole);
    }

    [Fact]
    public async Task CreatePendingUserAsync_CanCreateAsAdmin()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync();

        // Act
        var result = await _repository.CreatePendingUserAsync(workspace.Id, "pendingadmin@example.com", WorkspaceRole.WorkspaceAdmin);

        // Assert
        Assert.NotNull(result);

        // Verify WorkspaceUser membership has admin role
        var workspaceUser = await _context.WorkspaceUsers
            .FirstOrDefaultAsync(tu => tu.UserId == result.Id && tu.WorkspaceId == workspace.Id);
        Assert.NotNull(workspaceUser);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, workspaceUser.WorkspaceRole);
    }

    #endregion

    #region LinkUserAsync Tests

    [Fact]
    public async Task LinkUserAsync_LinksPendingUser()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync();
        var pendingUser = await _repository.CreatePendingUserAsync(workspace.Id, "tolink@example.com", WorkspaceRole.Normal);
        Assert.False(pendingUser.IsLinked);

        // Act
        var result = await _repository.LinkUserAsync(pendingUser.Id, IdentityProvider.Google, "google-linked-123");

        // Assert
        Assert.NotNull(result);
        Assert.Equal(IdentityProvider.Google, result.IdentityProvider);
        Assert.Equal("google-linked-123", result.ProviderSubjectId);
        Assert.True(result.IsLinked);
    }

    [Fact]
    public async Task LinkUserAsync_ReturnsNull_WhenUserNotFound()
    {
        // Act
        var result = await _repository.LinkUserAsync(999, IdentityProvider.Microsoft, "ms-999");

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region WorkspaceUserRepository - UpdateRoleAsync Tests

    [Fact]
    public async Task WorkspaceUserRepository_UpdateRoleAsync_UpdatesRole()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync();
        var user = await CreateTestUserAsync(workspace, "rolechange@example.com", WorkspaceRole.Normal);

        // Act
        var result = await _workspaceUserRepository.UpdateRoleAsync(user.Id, workspace.Id, WorkspaceRole.WorkspaceAdmin);

        _context.ChangeTracker.Clear();

        // Assert
        Assert.True(result);
        var workspaceUser = await _context.WorkspaceUsers
            .FirstOrDefaultAsync(tu => tu.UserId == user.Id && tu.WorkspaceId == workspace.Id);
        Assert.NotNull(workspaceUser);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, workspaceUser.WorkspaceRole);
    }

    [Fact]
    public async Task WorkspaceUserRepository_UpdateRoleAsync_ReturnsFalse_WhenMembershipNotFound()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync();

        // Act
        var result = await _workspaceUserRepository.UpdateRoleAsync(999, workspace.Id, WorkspaceRole.WorkspaceAdmin);

        // Assert
        Assert.False(result);
    }

    #endregion

    #region DeleteByIdAndWorkspaceAsync Tests

    [Fact]
    public async Task DeleteByIdAndWorkspaceAsync_DeletesMembership()
    {
        // Arrange
        var workspace1 = await CreateTestWorkspaceAsync();
        var workspace2 = new Workspace { Name = "second.com" };
        _context.Workspaces.Add(workspace2);
        await _context.SaveChangesAsync();

        // Create user with memberships in both workspaces
        var user = new User
        {
            ActiveWorkspaceId = workspace1.Id,
            Email = "deleteme@example.com",
            IdentityProvider = IdentityProvider.Microsoft,
            ProviderSubjectId = "ms-delete-me"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        _context.WorkspaceUsers.AddRange(
            new WorkspaceUser { UserId = user.Id, WorkspaceId = workspace1.Id, WorkspaceRole = WorkspaceRole.Normal },
            new WorkspaceUser { UserId = user.Id, WorkspaceId = workspace2.Id, WorkspaceRole = WorkspaceRole.Normal }
        );
        await _context.SaveChangesAsync();

        // Act - delete from workspace1, user should remain because they're still in workspace2
        var result = await _repository.DeleteByIdAndWorkspaceAsync(user.Id, workspace1.Id);

        // Assert
        Assert.True(result);

        // User should still exist
        var existingUser = await _context.Users.FindAsync(user.Id);
        Assert.NotNull(existingUser);

        // But membership in workspace1 should be gone
        var membership1 = await _context.WorkspaceUsers
            .FirstOrDefaultAsync(tu => tu.UserId == user.Id && tu.WorkspaceId == workspace1.Id);
        Assert.Null(membership1);

        // Membership in workspace2 should still exist
        var membership2 = await _context.WorkspaceUsers
            .FirstOrDefaultAsync(tu => tu.UserId == user.Id && tu.WorkspaceId == workspace2.Id);
        Assert.NotNull(membership2);
    }

    [Fact]
    public async Task DeleteByIdAndWorkspaceAsync_DeletesUserWhenLastMembership()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync();
        var user = await CreateTestUserAsync(workspace, "deleteme@example.com");
        var userId = user.Id;

        // Act - delete only membership
        var result = await _repository.DeleteByIdAndWorkspaceAsync(userId, workspace.Id);

        _context.ChangeTracker.Clear();

        // Assert
        Assert.True(result);

        // User should be deleted since it was their only membership
        var deletedUser = await _context.Users.FindAsync(userId);
        Assert.Null(deletedUser);
    }

    [Fact]
    public async Task DeleteByIdAndWorkspaceAsync_ReturnsFalse_WhenMembershipNotFound()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync();

        // Act
        var result = await _repository.DeleteByIdAndWorkspaceAsync(999, workspace.Id);

        // Assert
        Assert.False(result);
    }

    #endregion

    #region WorkspaceUserRepository - CountAdminsInWorkspaceAsync Tests

    [Fact]
    public async Task WorkspaceUserRepository_CountAdminsInWorkspaceAsync_CountsAdmins()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync();
        await CreateTestUserAsync(workspace, "admin1@example.com", WorkspaceRole.WorkspaceAdmin);
        await CreateTestUserAsync(workspace, "admin2@example.com", WorkspaceRole.WorkspaceAdmin);
        await CreateTestUserAsync(workspace, "normal@example.com", WorkspaceRole.Normal);

        // Act
        var count = await _workspaceUserRepository.CountAdminsInWorkspaceAsync(workspace.Id);

        // Assert
        Assert.Equal(2, count);
    }

    [Fact]
    public async Task WorkspaceUserRepository_CountAdminsInWorkspaceAsync_ReturnsZero_WhenNoAdmins()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync();
        await CreateTestUserAsync(workspace, "onlynormal@example.com", WorkspaceRole.Normal);

        // Act
        var count = await _workspaceUserRepository.CountAdminsInWorkspaceAsync(workspace.Id);

        // Assert
        Assert.Equal(0, count);
    }

    [Fact]
    public async Task WorkspaceUserRepository_CountAdminsInWorkspaceAsync_ReturnsZero_ForNonExistentWorkspace()
    {
        // Act
        var count = await _workspaceUserRepository.CountAdminsInWorkspaceAsync(999);

        // Assert
        Assert.Equal(0, count);
    }

    #endregion

    #region UpdateAsync Tests

    [Fact]
    public async Task UpdateAsync_SavesUserChanges()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync();
        var user = await CreateTestUserAsync(workspace, "update@example.com");

        var fetched = await _repository.GetByIdAsync(user.Id);
        fetched!.IsDeleted = true;
        fetched.DeletedAt = DateTime.UtcNow;

        // Act
        await _repository.UpdateAsync(fetched);

        // Assert
        _context.ChangeTracker.Clear();
        var saved = await _context.Users.FindAsync(user.Id);
        Assert.True(saved!.IsDeleted);
        Assert.NotNull(saved.DeletedAt);
    }

    [Fact]
    public async Task UpdateAsync_DoesNotUpdateActiveWorkspace_WhenNavigationIsPopulated()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync();
        var user = await CreateTestUserAsync(workspace, "graph@example.com");

        // Users fetched from the repository have ActiveWorkspace eagerly loaded
        var fetched = await _repository.GetByIdAsync(user.Id);
        Assert.NotNull(fetched!.ActiveWorkspace);

        fetched.IsDeleted = true;
        fetched.ActiveWorkspace!.Name = "Stale Workspace Name";

        // Act
        await _repository.UpdateAsync(fetched);

        // Assert - the user row is written but the stale workspace navigation is ignored
        _context.ChangeTracker.Clear();
        var savedUser = await _context.Users.FindAsync(user.Id);
        Assert.True(savedUser!.IsDeleted);
        var untouchedWorkspace = await _context.Workspaces.FindAsync(workspace.Id);
        Assert.Equal("test.example.com", untouchedWorkspace!.Name);
    }

    #endregion
}
