using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Workspaces;
using Microsoft.Extensions.Logging;
using Moq;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class WorkspaceUserSoftDeleteIntegrationTests : IDisposable, IAsyncLifetime
{
    private readonly AppDbContext _context;
    private readonly WorkspaceDeletionService _service;

    private readonly PostgresIntegrationFixture _fixture;

    public WorkspaceUserSoftDeleteIntegrationTests(PostgresIntegrationFixture fixture)
    {
        _fixture = fixture;
        _context = fixture.CreateContext();
        var loggerMock = new Mock<ILogger<WorkspaceDeletionService>>();

        var contextFactory = fixture.CreateContextFactory();

        _service = new WorkspaceDeletionService(
            contextFactory, TimeProvider.System, loggerMock.Object);
    }

    public Task InitializeAsync() => _fixture.ResetAsync();
    public Task DisposeAsync() => Task.CompletedTask;

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

        _context.ChangeTracker.Clear();

        // Assert
        Assert.True(result.Response!.UserSoftDeleted);

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
        Assert.False(result.Response!.UserSoftDeleted);
        Assert.Equal(workspace2.Id, result.Response!.NewActiveWorkspaceId);

        var notDeletedUser = await _context.Users.FindAsync(user.Id);
        Assert.False(notDeletedUser!.IsDeleted);
    }

    [Fact]
    public async Task FullFlow_SoleNormalMemberCannotDeleteWorkspace()
    {
        // The service enforces the same administrator policy as the HTTP endpoint.

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
        Assert.Equal(WorkspaceDeletionStatus.Forbidden, result.Status);
        Assert.Null(result.Response);
        _context.ChangeTracker.Clear();
        Assert.False((await _context.Workspaces.FindAsync(workspace.Id))!.IsDeleted);

        var notDeletedUser = await _context.Users.FindAsync(user.Id);
        Assert.False(notDeletedUser!.IsDeleted);
    }
}
