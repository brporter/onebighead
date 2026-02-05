using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using Microsoft.Extensions.Logging;
using Moq;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class WorkspaceUserSoftDeleteIntegrationTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly WorkspaceDeletionService _service;

    public WorkspaceUserSoftDeleteIntegrationTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        var loggerMock = new Mock<ILogger<WorkspaceDeletionService>>();

        var workspaceRepo = new WorkspaceRepository(_context);
        var workspaceUserRepo = new WorkspaceUserRepository(_context);
        var userRepo = new UserRepository(_context);

        _service = new WorkspaceDeletionService(
            _context, workspaceRepo, workspaceUserRepo, userRepo, loggerMock.Object);
    }

    public void Dispose() => _context.Dispose();

    [Fact]
    public async Task FullFlow_SingleWorkspaceAdminDeletesWorkspace_UserIsSoftDeleted()
    {
        // Arrange
        var workspace = new Workspace { Name = "Test", HasCompletedWelcome = true };
        _context.Workspaces.Add(workspace);
        await _context.SaveChangesAsync();

        var user = new User
        {
            Email = "test@test.com",
            ActiveWorkspaceId = workspace.Id,
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        _context.WorkspaceUsers.Add(new WorkspaceUser
        {
            UserId = user.Id,
            WorkspaceId = workspace.Id,
            WorkspaceRole = WorkspaceRole.WorkspaceAdmin
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _service.SoftDeleteWorkspaceAsync(workspace.Id, user.Id);

        // Assert
        Assert.True(result.UserSoftDeleted);

        var deletedUser = await _context.Users.FindAsync(user.Id);
        Assert.True(deletedUser!.IsDeleted);
        Assert.NotNull(deletedUser.DeletedAt);

        var deletedWorkspace = await _context.Workspaces.FindAsync(workspace.Id);
        Assert.True(deletedWorkspace!.IsDeleted);
    }

    [Fact]
    public async Task FullFlow_UserWithMultipleWorkspaces_OnlyWorkspaceDeleted()
    {
        // Arrange
        var workspace1 = new Workspace { Name = "Workspace 1", HasCompletedWelcome = true };
        var workspace2 = new Workspace { Name = "Workspace 2", HasCompletedWelcome = true };
        _context.Workspaces.AddRange(workspace1, workspace2);
        await _context.SaveChangesAsync();

        var user = new User
        {
            Email = "test@test.com",
            ActiveWorkspaceId = workspace1.Id,
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        _context.WorkspaceUsers.AddRange(
            new WorkspaceUser { UserId = user.Id, WorkspaceId = workspace1.Id, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
            new WorkspaceUser { UserId = user.Id, WorkspaceId = workspace2.Id, WorkspaceRole = WorkspaceRole.Normal }
        );
        await _context.SaveChangesAsync();

        // Act
        var result = await _service.SoftDeleteWorkspaceAsync(workspace1.Id, user.Id);

        // Assert
        Assert.False(result.UserSoftDeleted);
        Assert.Equal(workspace2.Id, result.NewActiveWorkspaceId);

        var notDeletedUser = await _context.Users.FindAsync(user.Id);
        Assert.False(notDeletedUser!.IsDeleted);
    }

    [Fact]
    public async Task FullFlow_NonAdminDeletesWorkspace_UserNotSoftDeleted()
    {
        // This test verifies that a normal member who somehow deletes a workspace
        // does NOT get soft-deleted (only WorkspaceAdmin should be soft-deleted)

        // Arrange
        var workspace = new Workspace { Name = "Test", HasCompletedWelcome = true };
        _context.Workspaces.Add(workspace);
        await _context.SaveChangesAsync();

        var user = new User
        {
            Email = "test@test.com",
            ActiveWorkspaceId = workspace.Id,
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // User is Normal, not WorkspaceAdmin
        _context.WorkspaceUsers.Add(new WorkspaceUser
        {
            UserId = user.Id,
            WorkspaceId = workspace.Id,
            WorkspaceRole = WorkspaceRole.Normal
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _service.SoftDeleteWorkspaceAsync(workspace.Id, user.Id);

        // Assert
        Assert.True(result.Success);
        Assert.False(result.UserSoftDeleted); // Not soft-deleted because not admin

        var notDeletedUser = await _context.Users.FindAsync(user.Id);
        Assert.False(notDeletedUser!.IsDeleted);
    }
}
