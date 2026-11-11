using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Tests.Unit.Services;

[Trait("Category", "Unit")]
public class WorkspaceRestorationServiceTests : IAsyncLifetime
{
    private readonly TestDbContextFactory _factory = new(new DbContextOptionsBuilder<AppDbContext>()
        .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
    private WorkspaceRestorationService Service => new(_factory, NullLogger<WorkspaceRestorationService>.Instance);

    public async Task InitializeAsync()
    {
        await using var context = _factory.CreateDbContext();
        context.Workspaces.AddRange(
            new Workspace { Id = 1, Name = "Current" },
            DeletedWorkspace(2), DeletedWorkspace(3), DeletedWorkspace(4));
        context.Users.Add(new User { Id = 1, Email = "collector@example.com", ActiveWorkspaceId = 1 });
        context.WorkspaceUsers.AddRange(Enumerable.Range(1, 3)
            .Select(id => new WorkspaceUser { UserId = 1, WorkspaceId = id, WorkspaceRole = WorkspaceRole.WorkspaceAdmin }));
        await context.SaveChangesAsync();
    }

    private static Workspace DeletedWorkspace(int id) => new()
    {
        Id = id, Name = $"Archive {id}", IsDeleted = true,
        DeletedAt = DateTime.UtcNow.AddDays(-2), DeletedByUserId = 1
    };

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Batch_RestoresDistinctDeletedSelectionsInOrder_AndActivatesFirstRestored()
    {
        var result = await Service.RestoreAndActivateAsync(1, [1, 3, 2, 3]);
        Assert.True(result.IsAuthorized);
        Assert.Equal(new[] { 3, 2 }, result.RestoredWorkspaces.Select(w => w.Id));
        Assert.Equal(3, Assert.IsType<User>(result.ActiveUser).ActiveWorkspaceId);
        await using var context = _factory.CreateDbContext();
        Assert.Equal(3, (await context.Users.SingleAsync()).ActiveWorkspaceId);
        foreach (var id in new[] { 2, 3 })
        {
            var workspace = await context.Workspaces.SingleAsync(w => w.Id == id);
            Assert.False(workspace.IsDeleted);
            Assert.Null(workspace.DeletedAt);
            Assert.Null(workspace.DeletedByUserId);
        }
        Assert.True((await context.Workspaces.SingleAsync(w => w.Id == 4)).IsDeleted);
    }

    [Fact]
    public async Task SingleRestore_LeavesActiveWorkspaceUnchanged_AndRepeatedRestoreHasNoChanges()
    {
        var result = await Service.RestoreAsync(1, 2);
        Assert.True(result.IsAuthorized);
        Assert.Equal(2, Assert.Single(result.RestoredWorkspaces).Id);
        Assert.Null(result.ActiveUser);
        var repeated = await Service.RestoreAsync(1, 2);
        Assert.True(repeated.IsAuthorized);
        Assert.Empty(repeated.RestoredWorkspaces);
        Assert.Null(repeated.ActiveUser);
        await using var context = _factory.CreateDbContext();
        Assert.Equal(1, (await context.Users.SingleAsync()).ActiveWorkspaceId);
    }

    [Fact]
    public async Task BatchOfActiveWorkspaces_DoesNotSwitchTheSession()
    {
        var result = await Service.RestoreAndActivateAsync(1, [1, 1]);
        Assert.True(result.IsAuthorized);
        Assert.Empty(result.RestoredWorkspaces);
        Assert.Null(result.ActiveUser);
        await AssertUnchangedAsync();
    }

    [Theory]
    [InlineData(4)] // Existing workspace without membership.
    [InlineData(99)] // Missing workspace.
    public async Task LaterMissingMembership_RejectsEntireSelection(int otherWorkspaceId)
    {
        var result = await Service.RestoreAndActivateAsync(1, [2, otherWorkspaceId]);
        Assert.False(result.IsAuthorized);
        Assert.Empty(result.RestoredWorkspaces);
        Assert.Null(result.ActiveUser);
        await AssertUnchangedAsync();
    }

    [Fact]
    public async Task LaterNonAdminMembership_RejectsEntireSelection()
    {
        await using (var context = _factory.CreateDbContext())
        {
            (await context.WorkspaceUsers.SingleAsync(m => m.WorkspaceId == 3)).WorkspaceRole = WorkspaceRole.Normal;
            await context.SaveChangesAsync();
        }
        Assert.False((await Service.RestoreAndActivateAsync(1, [2, 3])).IsAuthorized);
        await AssertUnchangedAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MissingOrDeletedUser_CannotRestoreWithAStaleIdentity(bool deleted)
    {
        await using (var context = _factory.CreateDbContext())
        {
            var user = await context.Users.SingleAsync();
            if (deleted) user.IsDeleted = true;
            else context.Users.Remove(user);
            await context.SaveChangesAsync();
        }
        Assert.False((await Service.RestoreAndActivateAsync(1, [2])).IsAuthorized);
        await using var verification = _factory.CreateDbContext();
        Assert.True((await verification.Workspaces.SingleAsync(w => w.Id == 2)).IsDeleted);
    }

    [Fact]
    public async Task EmptySelection_IsRejectedBeforeOpeningTheDatabase()
    {
        var exception = await Assert.ThrowsAsync<ArgumentException>(() => Service.RestoreAndActivateAsync(1, []));
        Assert.Equal("workspaceIds", exception.ParamName);
        await AssertUnchangedAsync();
    }

    [Fact]
    public async Task CancelledRequest_DoesNotRestoreAnything()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Service.RestoreAndActivateAsync(1, [2], cancellation.Token));
        await AssertUnchangedAsync();
    }

    private async Task AssertUnchangedAsync()
    {
        await using var context = _factory.CreateDbContext();
        Assert.Equal(1, (await context.Users.SingleAsync()).ActiveWorkspaceId);
        Assert.All(await context.Workspaces.Where(w => w.Id > 1).ToListAsync(), workspace =>
        {
            Assert.True(workspace.IsDeleted);
            Assert.NotNull(workspace.DeletedAt);
            Assert.Equal(1, workspace.DeletedByUserId);
        });
    }
}
