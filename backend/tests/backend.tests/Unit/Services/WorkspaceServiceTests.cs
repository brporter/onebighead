using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;

namespace OneBigHead.Server.Tests.Unit.Services;

public class WorkspaceServiceTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly WorkspaceService _service;
    private readonly Mock<ILogger<WorkspaceService>> _loggerMock;

    public WorkspaceServiceTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _loggerMock = new Mock<ILogger<WorkspaceService>>();

        var workspaceRepo = new WorkspaceRepository(_context);
        var workspaceUserRepo = new WorkspaceUserRepository(_context);
        var userRepo = new UserRepository(_context);

        _service = new WorkspaceService(
            _context, workspaceRepo, workspaceUserRepo, userRepo, _loggerMock.Object);
    }

    public void Dispose() => _context.Dispose();

    [Fact]
    public async Task SoftDeleteWorkspaceAsync_SoftDeletesUser_WhenSingleWorkspaceAdmin()
    {
        // Arrange: User is admin of exactly one workspace, no other memberships
        var workspace = new Workspace { Name = "Only Workspace", HasCompletedWelcome = true };
        _context.Workspaces.Add(workspace);
        await _context.SaveChangesAsync();

        var user = new User
        {
            Email = "admin@test.com",
            ActiveWorkspaceId = workspace.Id,
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        var membership = new WorkspaceUser
        {
            UserId = user.Id,
            WorkspaceId = workspace.Id,
            WorkspaceRole = WorkspaceRole.WorkspaceAdmin
        };
        _context.WorkspaceUsers.Add(membership);
        await _context.SaveChangesAsync();

        // Act
        var result = await _service.SoftDeleteWorkspaceAsync(workspace.Id, user.Id);

        // Assert
        Assert.True(result.Success);
        Assert.True(result.UserSoftDeleted);

        var deletedUser = await _context.Users.FindAsync(user.Id);
        Assert.True(deletedUser!.IsDeleted);
        Assert.NotNull(deletedUser.DeletedAt);
    }

    [Fact]
    public async Task SoftDeleteWorkspaceAsync_DoesNotSoftDeleteUser_WhenUserHasOtherWorkspaces()
    {
        // Arrange: User is admin of one workspace but member of another
        var workspace1 = new Workspace { Name = "Workspace 1", HasCompletedWelcome = true };
        var workspace2 = new Workspace { Name = "Workspace 2", HasCompletedWelcome = true };
        _context.Workspaces.AddRange(workspace1, workspace2);
        await _context.SaveChangesAsync();

        var user = new User
        {
            Email = "admin@test.com",
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
        Assert.True(result.Success);
        Assert.False(result.UserSoftDeleted);
        Assert.Equal(workspace2.Id, result.NewActiveWorkspaceId);

        var notDeletedUser = await _context.Users.FindAsync(user.Id);
        Assert.False(notDeletedUser!.IsDeleted);
    }
}
