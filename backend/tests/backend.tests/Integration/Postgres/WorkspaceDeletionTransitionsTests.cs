using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class WorkspaceDeletionTransitionsTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private readonly IDbContextFactory<AppDbContext> _factory = fixture.CreateContextFactory();
    private static readonly DateTimeOffset Now = new(2026, 1, 20, 12, 0, 0, TimeSpan.Zero);
    private WorkspaceDeletionService Service => new(_factory, new FixedTime(), NullLogger<WorkspaceDeletionService>.Instance);

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var context = _factory.CreateDbContext();
        context.Workspaces.AddRange(Enumerable.Range(1, 4).Select(id => new Workspace { Id = id, Name = $"Workspace {id}", IsDeleted = id == 2 }));
        context.Users.AddRange(Enumerable.Range(1, 5).Select(id => new User { Id = id, ActiveWorkspaceId = id == 4 ? 4 : 1 }));
        context.WorkspaceUsers.AddRange(
            Membership(1, 1, WorkspaceRole.WorkspaceAdmin), Membership(1, 2), Membership(1, 4), Membership(1, 3),
            Membership(2, 1), Membership(2, 4), Membership(3, 1), Membership(4, 1), Membership(4, 4));
        await context.SaveChangesAsync();
    }

    private static WorkspaceUser Membership(int userId, int workspaceId, WorkspaceRole role = WorkspaceRole.Normal) =>
        new() { UserId = userId, WorkspaceId = workspaceId, WorkspaceRole = role };
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Deletion_SwitchesEachAffectedUserToTheirFirstActiveMembership()
    {
        var result = await Service.SoftDeleteWorkspaceAsync(1, 1);
        Assert.True(result.Response!.Success);
        Assert.False(result.Response!.UserSoftDeleted);
        Assert.Equal(3, result.Response!.NewActiveWorkspaceId);
        Assert.Equal(3, result.Session!.User.ActiveWorkspaceId);
        Assert.Equal(WorkspaceRole.Normal, result.Session.Response.WorkspaceRole);
        await using var context = _factory.CreateDbContext();
        var users = await context.Users.OrderBy(u => u.Id).ToListAsync();
        Assert.Equal(new int?[] { 3, 4, null, 4, null }, users.Select(u => u.ActiveWorkspaceId));
        Assert.All(users, user => Assert.False(user.IsDeleted));
        var workspace = await context.Workspaces.SingleAsync(w => w.Id == 1);
        Assert.True(workspace.IsDeleted);
        Assert.Equal(Now.UtcDateTime, workspace.DeletedAt);
        Assert.Equal(1, workspace.DeletedByUserId);
        Assert.Equal(9, await context.WorkspaceUsers.CountAsync());
    }

    [Fact]
    public async Task DeletingNonActiveWorkspace_DoesNotSwitchTheRequestingUser()
    {
        await using (var context = _factory.CreateDbContext())
        {
            (await context.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId = 4;
            await context.SaveChangesAsync();
        }
        var result = await Service.SoftDeleteWorkspaceAsync(1, 1);
        Assert.True(result.Response!.Success);
        Assert.Null(result.Response!.NewActiveWorkspaceId);
        await using var verification = _factory.CreateDbContext();
        Assert.Equal(4, (await verification.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
    }

    [Fact]
    public async Task OtherDeletedMembership_PreservesAccountForRecoveryWithoutChoosingDeletedWorkspace()
    {
        await using (var context = _factory.CreateDbContext())
        {
            context.WorkspaceUsers.RemoveRange(context.WorkspaceUsers.Where(m => m.UserId == 1 && m.WorkspaceId > 2));
            await context.SaveChangesAsync();
        }
        var result = await Service.SoftDeleteWorkspaceAsync(1, 1);
        Assert.True(result.Response!.Success);
        Assert.False(result.Response!.UserSoftDeleted);
        Assert.Null(result.Response!.NewActiveWorkspaceId);
        Assert.Null(result.Session!.User.ActiveWorkspaceId);
        Assert.Empty(result.Session.Response.Workspaces);
        await using var check = _factory.CreateDbContext();
        Assert.Null((await check.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(99)]
    public async Task DeletedOrMissingWorkspace_CannotBeDeletedAgain(int workspaceId)
    {
        Assert.Equal(WorkspaceDeletionStatus.NotFound, (await Service.SoftDeleteWorkspaceAsync(workspaceId, 1)).Status);
        await AssertCurrentWorkspaceUnchangedAsync();
    }

    [Theory]
    [InlineData(99)] // Missing account.
    [InlineData(5)] // Non-member.
    [InlineData(2)] // Non-admin in a shared workspace.
    public async Task IneligibleCaller_CannotDeleteWorkspace(int userId)
    {
        Assert.NotEqual(WorkspaceDeletionStatus.Deleted, (await Service.SoftDeleteWorkspaceAsync(1, userId)).Status);
        await AssertCurrentWorkspaceUnchangedAsync();
    }

    [Fact]
    public async Task DeletedCaller_CannotDeleteWorkspaceWithStaleIdentity()
    {
        await using (var context = _factory.CreateDbContext())
        {
            (await context.Users.SingleAsync(u => u.Id == 1)).IsDeleted = true;
            await context.SaveChangesAsync();
        }
        Assert.Equal(WorkspaceDeletionStatus.NotFound, (await Service.SoftDeleteWorkspaceAsync(1, 1)).Status);
        await AssertCurrentWorkspaceUnchangedAsync();
    }

    private async Task AssertCurrentWorkspaceUnchangedAsync()
    {
        await using var context = _factory.CreateDbContext();
        Assert.False((await context.Workspaces.SingleAsync(w => w.Id == 1)).IsDeleted);
        Assert.Equal(1, (await context.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
    }

    private sealed class FixedTime : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
