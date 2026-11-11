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

    public UserRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning))
            .Options;

        _context = new AppDbContext(options);
        var contextFactory = new TestDbContextFactory(options);
        _repository = new UserRepository(contextFactory);
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
