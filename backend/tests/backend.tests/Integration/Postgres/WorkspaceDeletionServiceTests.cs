using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Npgsql;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Workspaces;
using OneBigHead.Server.Services.Memberships;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class WorkspaceDeletionServiceTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var context = fixture.CreateContext();
        context.Workspaces.AddRange(new Workspace { Id = 1, Name = "Current" }, new Workspace { Id = 2, Name = "Alternative" });
        context.Users.AddRange(new User { Id = 1, ActiveWorkspaceId = 1, Email = "admin@example.com" }, new User { Id = 2, ActiveWorkspaceId = 1, Email = "member@example.com" });
        context.WorkspaceUsers.AddRange(
            new WorkspaceUser { UserId = 1, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
            new WorkspaceUser { UserId = 2, WorkspaceId = 1 }, new WorkspaceUser { UserId = 2, WorkspaceId = 2 });
        await context.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task ConcurrentDeletions_CommitOnlyOneReviewedOutcome()
    {
        var service = Service(new SynchronizedSaves());
        var results = await Task.WhenAll(service.SoftDeleteWorkspaceAsync(1, 1), service.SoftDeleteWorkspaceAsync(1, 1))
            .WaitAsync(TimeSpan.FromSeconds(20));
        Assert.Single(results, r => r.Status == WorkspaceDeletionStatus.Deleted);
        var conflict = Assert.Single(results, r => r.Status == WorkspaceDeletionStatus.Conflict);
        Assert.Null(conflict.Response);
        Assert.Null(conflict.Session);
        Assert.Contains("Reload", conflict.Error);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConcurrentAdministratorDemotionOrRemoval_PreventsStaleDeletion(bool remove)
    {
        await using (var setup = fixture.CreateContext())
            await setup.WorkspaceUsers.Where(m => m.UserId == 2 && m.WorkspaceId == 1).ExecuteUpdateAsync(s => s.SetProperty(m => m.WorkspaceRole, WorkspaceRole.WorkspaceAdmin));
        var change = new BeforeMembershipSave(async () =>
        {
            var team = new TeamMembershipChanges(fixture.CreateContextFactory(), TimeProvider.System, NullLogger<TeamMembershipChanges>.Instance);
            var result = remove ? await team.RemoveAsync(2, 1, 1) : await team.ChangeRoleAsync(2, 1, 1, WorkspaceRole.Normal);
            Assert.Equal(TeamMembershipStatus.Changed, result.Status);
        });
        Assert.Equal(WorkspaceDeletionStatus.Conflict, (await Service(change).SoftDeleteWorkspaceAsync(1, 1)).Status);
        await using var check = fixture.CreateContext();
        Assert.False((await check.Workspaces.SingleAsync(w => w.Id == 1)).IsDeleted);
        Assert.False((await check.Users.SingleAsync(u => u.Id == 1)).IsDeleted);
    }

    [Fact]
    public async Task ConcurrentAlternativeDeletion_DoesNotSelectAnUnavailableWorkspace()
    {
        var change = new BeforeMembershipSave(async () =>
        {
            await using var db = fixture.CreateContext();
            // The real deletion command reads all affected assignments, creating
            // the serialization dependency that a detached update used to miss.
            await db.WorkspaceUsers.Where(m => m.UserId == 2 && m.WorkspaceId == 2).ExecuteUpdateAsync(s => s.SetProperty(m => m.WorkspaceRole, WorkspaceRole.WorkspaceAdmin));
            Assert.Equal(WorkspaceDeletionStatus.Deleted, (await Service().SoftDeleteWorkspaceAsync(2, 2)).Status);
        });
        Assert.Equal(WorkspaceDeletionStatus.Conflict, (await Service(change).SoftDeleteWorkspaceAsync(1, 1)).Status);
        await using var check = fixture.CreateContext();
        Assert.False((await check.Workspaces.SingleAsync(w => w.Id == 1)).IsDeleted);
        Assert.True((await check.Workspaces.SingleAsync(w => w.Id == 2)).IsDeleted);
        Assert.Equal(1, (await check.Users.SingleAsync(u => u.Id == 2)).ActiveWorkspaceId);
    }

    [Fact]
    public async Task DeferredCommitFailure_RollsBackWorkspaceAccountAndAssignments()
    {
        await using var db = fixture.CreateContext();
        await db.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION workspace_deletion_failure() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'Workspace deletion test failure'; END $$
            """);
        await db.Database.ExecuteSqlRawAsync("""
            CREATE CONSTRAINT TRIGGER workspace_deletion_failure AFTER UPDATE ON "Workspaces"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION workspace_deletion_failure()
            """);
        try
        {
            var observer = new ObserveDeletion();
            var logger = new Mock<ILogger<WorkspaceDeletionService>>(MockBehavior.Strict);
            var factory = new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString).AddInterceptors(observer).Options);
            await Assert.ThrowsAsync<PostgresException>(() => new WorkspaceDeletionService(factory, TimeProvider.System, logger.Object).SoftDeleteWorkspaceAsync(1, 1));
            Assert.True(observer.Verified);
            logger.VerifyNoOtherCalls();
            Assert.False((await db.Workspaces.SingleAsync(w => w.Id == 1)).IsDeleted);
            Assert.All(await db.Users.ToListAsync(), user => { Assert.False(user.IsDeleted); Assert.Equal(1, user.ActiveWorkspaceId); });
        }
        finally
        {
            await db.Database.ExecuteSqlRawAsync("DROP TRIGGER workspace_deletion_failure ON \"Workspaces\"");
            await db.Database.ExecuteSqlRawAsync("DROP FUNCTION workspace_deletion_failure()");
        }
    }

    private WorkspaceDeletionService Service(params IInterceptor[] interceptors) => new(new TestDbContextFactory(
        new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString).AddInterceptors(interceptors).Options), TimeProvider.System, NullLogger<WorkspaceDeletionService>.Instance);

    private sealed class ObserveDeletion : SaveChangesInterceptor
    {
        public bool Verified { get; private set; }
        public override async ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            var db = (AppDbContext)eventData.Context!;
            Assert.True((await db.Workspaces.SingleAsync(w => w.Id == 1, cancellationToken)).IsDeleted);
            Assert.True((await db.Users.SingleAsync(u => u.Id == 1, cancellationToken)).IsDeleted);
            Assert.Equal(2, (await db.Users.SingleAsync(u => u.Id == 2, cancellationToken)).ActiveWorkspaceId);
            Verified = true;
            return result;
        }
    }

    [Fact]
    public async Task Deletion_CommitsAccountPolicyAndAffectedMembershipSwitchesTogether()
    {
        var service = new WorkspaceDeletionService(fixture.CreateContextFactory(), TimeProvider.System, NullLogger<WorkspaceDeletionService>.Instance);
        var result = await service.SoftDeleteWorkspaceAsync(1, 1);
        Assert.True(result.Response!.Success);
        Assert.True(result.Response!.UserSoftDeleted);
        Assert.Null(result.Response!.NewActiveWorkspaceId);
        await using var context = fixture.CreateContext();
        var workspace = await context.Workspaces.SingleAsync(w => w.Id == 1);
        var admin = await context.Users.SingleAsync(u => u.Id == 1);
        Assert.True(workspace.IsDeleted);
        Assert.Equal(1, workspace.DeletedByUserId);
        Assert.True(admin.IsDeleted);
        Assert.NotNull(workspace.DeletedAt);
        Assert.Equal(workspace.DeletedAt, admin.DeletedAt);
        Assert.Equal(2, (await context.Users.SingleAsync(u => u.Id == 2)).ActiveWorkspaceId);
        Assert.Equal(3, await context.WorkspaceUsers.CountAsync());
    }

    [Fact]
    public async Task WorkspaceSaveFailure_RollsBackAlreadyExecutedUserDeletionAndSwitches()
    {
        await using var context = fixture.CreateContext();
        await context.Database.ExecuteSqlRawAsync("""
            ALTER TABLE "Workspaces" ADD CONSTRAINT "DeletionRollbackTest" CHECK ("Id" <> 1 OR NOT "IsDeleted")
            """);
        try
        {
            var commands = new CompletedUpdates();
            var options = new DbContextOptionsBuilder<AppDbContext>()
                .UseNpgsql(fixture.ConnectionString, postgres => postgres.MaxBatchSize(1)).AddInterceptors(commands).Options;
            var logger = new Mock<ILogger<WorkspaceDeletionService>>(MockBehavior.Strict);
            var service = new WorkspaceDeletionService(new TestDbContextFactory(options), TimeProvider.System, logger.Object);
            await Assert.ThrowsAsync<DbUpdateException>(() => service.SoftDeleteWorkspaceAsync(1, 1));
            Assert.Equal(2, commands.Tables.Count(table => table == "Users"));
            logger.VerifyNoOtherCalls();
            var workspace = await context.Workspaces.SingleAsync(w => w.Id == 1);
            Assert.False(workspace.IsDeleted);
            Assert.Null(workspace.DeletedAt);
            Assert.Null(workspace.DeletedByUserId);
            Assert.All(await context.Users.ToListAsync(), user =>
            {
                Assert.False(user.IsDeleted);
                Assert.Null(user.DeletedAt);
                Assert.Equal(1, user.ActiveWorkspaceId);
            });
        }
        finally
        {
            await context.Database.ExecuteSqlRawAsync("""
                ALTER TABLE "Workspaces" DROP CONSTRAINT "DeletionRollbackTest"
                """, CancellationToken.None);
        }
    }
}
