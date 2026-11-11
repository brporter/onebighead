using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class WorkspaceDeletionAccountPolicyTests : IDisposable, IAsyncLifetime
{
    private readonly AppDbContext _context;
    private readonly WorkspaceDeletionService _service;
    private readonly Mock<ILogger<WorkspaceDeletionService>> _loggerMock;

    private readonly PostgresIntegrationFixture _fixture;

    public WorkspaceDeletionAccountPolicyTests(PostgresIntegrationFixture fixture)
    {
        _fixture = fixture;
        _context = fixture.CreateContext();
        _loggerMock = new Mock<ILogger<WorkspaceDeletionService>>();

        var contextFactory = fixture.CreateContextFactory();

        _service = new WorkspaceDeletionService(
            contextFactory, TimeProvider.System, _loggerMock.Object);
    }

    public Task InitializeAsync() => _fixture.ResetAsync();
    public Task DisposeAsync() => Task.CompletedTask;

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

        _context.ChangeTracker.Clear();

        // Assert
        Assert.True(result.Response!.Success);
        Assert.True(result.Response!.UserSoftDeleted);

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
        Assert.True(result.Response!.Success);
        Assert.False(result.Response!.UserSoftDeleted);
        Assert.Equal(workspace2.Id, result.Response!.NewActiveWorkspaceId);

        var notDeletedUser = await _context.Users.FindAsync(user.Id);
        Assert.False(notDeletedUser!.IsDeleted);
    }
}
