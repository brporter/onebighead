using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Npgsql;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Accounts;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class AccountDeletionTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 12, 0, 0, TimeSpan.Zero);

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var db = fixture.CreateContext();
        db.Workspaces.AddRange(Enumerable.Range(1, 4).Select(id => new Workspace
        {
            Id = id, Name = $"Workspace {id}", IsDeleted = id == 4,
            DeletedAt = id == 4 ? Now.AddDays(-1).UtcDateTime : null
        }));
        db.Users.AddRange(new User { Id = 1, ActiveWorkspaceId = 1, Email = "owner@example.test" },
            new User { Id = 2, ActiveWorkspaceId = 2, Email = "member@example.test" },
            new User { Id = 3, ActiveWorkspaceId = 2, Email = "deleted@example.test", IsDeleted = true });
        db.WorkspaceUsers.AddRange(Enumerable.Range(1, 4).Select(id => new WorkspaceUser
            { UserId = 1, WorkspaceId = id, WorkspaceRole = WorkspaceRole.WorkspaceAdmin }));
        db.WorkspaceUsers.AddRange(new WorkspaceUser { UserId = 2, WorkspaceId = 2 },
            new WorkspaceUser { UserId = 2, WorkspaceId = 3, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
            new WorkspaceUser { UserId = 3, WorkspaceId = 2, WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
        db.Collections.AddRange(new Collection { Id = 1, WorkspaceId = 1, Name = "Private collection" },
            new Collection { Id = 2, WorkspaceId = 2, Name = "Shared collection" });
        db.SupportRequests.Add(new SupportRequest { Id = 1, UserId = 1, Email = "owner@example.test", Subject = "Question", Description = "Keep support history" });
        db.SupportReplies.Add(new SupportReply { Id = 1, SupportRequestId = 1, UserId = 1, Message = "Reply" });
        db.ContentScanLogs.Add(new ContentScanLog { Id = Guid.NewGuid(), UserId = 1, WorkspaceId = 1, ScannedAt = Now.UtcDateTime });
        db.TokenRevocations.Add(new TokenRevocation { UserId = 1, RevokedAtUtc = Now.UtcDateTime });
        await db.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Preview_UsesCurrentMembershipsAndExcludesDeletedRecipientsWithoutWriting()
    {
        var reader = new AccountDeletionReader(fixture.CreateContextFactory());
        Assert.Null(await reader.ReadAsync(999));
        var info = Assert.IsType<UserDeletionInfoResponse>(await reader.ReadAsync(1));
        Assert.Equal(new[] { 1, 2, 3 }, info.WorkspaceMemberships.Select(m => m.WorkspaceId));
        Assert.Equal(2, info.WorkspacesRequiringAction);
        Assert.Equal(2, Assert.Single(info.WorkspaceMemberships[1].OtherUsers).UserId);
        Assert.True(info.WorkspaceMemberships[1].IsOnlyAdmin);
        Assert.True(info.WorkspaceMemberships[2].CanLeave);
        await AssertUnchanged();
    }

    [Fact]
    public async Task Delete_CommitsAllResolutionsAndPreservesSharedContentAndHistory()
    {
        Assert.Equal(AccountDeletionStatus.Deleted, (await Commands().DeleteAsync(1, Request())).Status);
        await using var db = fixture.CreateContext();
        Assert.False(await db.Users.AnyAsync(u => u.Id == 1));
        Assert.False(await db.WorkspaceUsers.AnyAsync(m => m.UserId == 1));
        Assert.Empty(await db.TokenRevocations.ToListAsync());
        var sole = await db.Workspaces.SingleAsync(w => w.Id == 1);
        Assert.True(sole.IsDeleted);
        Assert.Equal(Now.UtcDateTime, sole.DeletedAt);
        Assert.Equal(1, sole.DeletedByUserId);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, (await db.WorkspaceUsers.SingleAsync(m => m.WorkspaceId == 2 && m.UserId == 2)).WorkspaceRole);
        Assert.All(await db.Workspaces.Where(w => w.Id == 2 || w.Id == 3).ToListAsync(), w => Assert.False(w.IsDeleted));
        Assert.Equal(Now.AddDays(-1).UtcDateTime, (await db.Workspaces.SingleAsync(w => w.Id == 4)).DeletedAt);
        Assert.Equal(2, await db.Collections.CountAsync());
        Assert.Equal(2, await db.Users.CountAsync());
        Assert.Null((await db.SupportRequests.SingleAsync()).UserId);
        Assert.Null((await db.SupportReplies.SingleAsync()).UserId);
        Assert.Equal(1, (await db.ContentScanLogs.SingleAsync()).UserId);
        Assert.Equal(AccountDeletionStatus.Invalid, (await Commands().DeleteAsync(1, Request())).Status);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AccountWithoutActiveMemberships_CanBePermanentlyDeleted(bool softDeleted)
    {
        await using (var db = fixture.CreateContext())
        {
            db.WorkspaceUsers.RemoveRange(await db.WorkspaceUsers.Where(m => m.UserId == 1 && (m.WorkspaceId != 4 || !softDeleted)).ToListAsync());
            var user = await db.Users.SingleAsync(u => u.Id == 1);
            user.ActiveWorkspaceId = softDeleted ? 4 : null;
            user.IsDeleted = softDeleted;
            await db.SaveChangesAsync();
        }
        var preview = await new AccountDeletionReader(fixture.CreateContextFactory()).ReadAsync(1);
        Assert.True(preview!.CanDeleteImmediately);
        Assert.Empty(preview.WorkspaceMemberships);
        Assert.Equal(AccountDeletionStatus.Deleted, (await Commands().DeleteAsync(1, new() { ConfirmEmail = "OWNER@example.test" })).Status);
        await using var check = fixture.CreateContext();
        Assert.False(await check.Users.AnyAsync(u => u.Id == 1));
        Assert.False((await check.Workspaces.SingleAsync(w => w.Id == 1)).IsDeleted);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InvalidLaterResolution_DoesNotCommitEarlierWorkspaceDeletion(bool deletedRecipient)
    {
        var request = Request();
        if (deletedRecipient) request.WorkspaceActions[1].TransferToUserId = 3;
        else request.WorkspaceActions.RemoveAt(1);
        Assert.Equal(AccountDeletionStatus.Invalid, (await Commands().DeleteAsync(1, request)).Status);
        await AssertUnchanged();
    }

    [Fact]
    public async Task CommitFailure_AfterAllWrites_RollsBackAccountMembershipsTransfersAndWorkspace()
    {
        await using var setup = fixture.CreateContext();
        await setup.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION account_deletion_failure() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'Account deletion test failure'; END $$
            """);
        await setup.Database.ExecuteSqlRawAsync("""
            CREATE CONSTRAINT TRIGGER account_deletion_failure AFTER DELETE ON "Users"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION account_deletion_failure()
            """);
        try
        {
            var observation = new ObserveSaved();
            var logger = new Mock<ILogger<AccountDeletion>>(MockBehavior.Strict);
            var options = new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString).AddInterceptors(observation).Options;
            var command = new AccountDeletion(new TestDbContextFactory(options), new Clock(), logger.Object);
            await Assert.ThrowsAsync<PostgresException>(() => command.DeleteAsync(1, Request()));
            Assert.True(observation.WritesVerified);
            logger.VerifyNoOtherCalls();
            await AssertUnchanged();
        }
        finally
        {
            await setup.Database.ExecuteSqlRawAsync("DROP TRIGGER account_deletion_failure ON \"Users\"");
            await setup.Database.ExecuteSqlRawAsync("DROP FUNCTION account_deletion_failure()");
        }
    }

    [Fact]
    public async Task CompetingAccountDeletions_CommitOnceAndReturnAConflict()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString).AddInterceptors(new BothLoaded()).Options;
        var commands = new AccountDeletion(new TestDbContextFactory(options), new Clock(), NullLogger<AccountDeletion>.Instance);
        var outcomes = await Task.WhenAll(commands.DeleteAsync(1, Request()), commands.DeleteAsync(1, Request())).WaitAsync(TimeSpan.FromSeconds(20));
        Assert.Contains(outcomes, o => o.Status == AccountDeletionStatus.Deleted);
        Assert.Contains(outcomes, o => o.Status == AccountDeletionStatus.Conflict && o.Error!.Contains("Reload"));
        await using var db = fixture.CreateContext();
        Assert.False(await db.Users.AnyAsync(u => u.Id == 1));
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, (await db.WorkspaceUsers.SingleAsync(m => m.UserId == 2 && m.WorkspaceId == 2)).WorkspaceRole);
    }

    [Fact]
    public async Task TargetMembershipRemovedAfterSnapshot_RejectsStaleTransferAndRollsBackDeletion()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString)
            .AddInterceptors(new BeforeSave(async () =>
            {
                await using var db = fixture.CreateContext();
                await db.WorkspaceUsers.Where(m => m.UserId == 2 && m.WorkspaceId == 2).ExecuteDeleteAsync();
            })).Options;
        var commands = new AccountDeletion(new TestDbContextFactory(options), new Clock(), NullLogger<AccountDeletion>.Instance);
        Assert.Equal(AccountDeletionStatus.Conflict, (await commands.DeleteAsync(1, Request())).Status);
        await using var check = fixture.CreateContext();
        Assert.True(await check.Users.AnyAsync(u => u.Id == 1));
        Assert.Equal(4, await check.WorkspaceUsers.CountAsync(m => m.UserId == 1));
        Assert.False((await check.Workspaces.SingleAsync(w => w.Id == 1)).IsDeleted);
        Assert.Equal(1, (await check.SupportRequests.SingleAsync()).UserId);
    }

    private AccountDeletion Commands() => new(fixture.CreateContextFactory(), new Clock(), NullLogger<AccountDeletion>.Instance);
    private static DeleteUserRequest Request() => new()
    {
        ConfirmEmail = "owner@example.test",
        WorkspaceActions = [new() { WorkspaceId = 1, Action = WorkspaceActionType.Delete },
            new() { WorkspaceId = 2, Action = WorkspaceActionType.Transfer, TransferToUserId = 2 }]
    };

    private async Task AssertUnchanged()
    {
        await using var db = fixture.CreateContext();
        Assert.Equal(3, await db.Users.CountAsync());
        Assert.Equal(7, await db.WorkspaceUsers.CountAsync());
        Assert.False((await db.Workspaces.SingleAsync(w => w.Id == 1)).IsDeleted);
        Assert.Equal(WorkspaceRole.Normal, (await db.WorkspaceUsers.SingleAsync(m => m.UserId == 2 && m.WorkspaceId == 2)).WorkspaceRole);
        Assert.Equal(1, (await db.SupportRequests.SingleAsync()).UserId);
        Assert.Equal(1, (await db.SupportReplies.SingleAsync()).UserId);
        Assert.Equal(1, (await db.TokenRevocations.SingleAsync()).UserId);
    }

    private sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class ObserveSaved : SaveChangesInterceptor
    {
        public bool WritesVerified { get; private set; }
        public override async ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            var db = (AppDbContext)eventData.Context!;
            Assert.False(await db.Users.AnyAsync(u => u.Id == 1, cancellationToken));
            Assert.False(await db.WorkspaceUsers.AnyAsync(m => m.UserId == 1, cancellationToken));
            Assert.True(await db.Workspaces.Where(w => w.Id == 1).Select(w => w.IsDeleted).SingleAsync(cancellationToken));
            Assert.Equal(WorkspaceRole.WorkspaceAdmin, await db.WorkspaceUsers.Where(m => m.UserId == 2 && m.WorkspaceId == 2)
                .Select(m => m.WorkspaceRole).SingleAsync(cancellationToken));
            WritesVerified = true;
            return result;
        }
    }

    private sealed class BothLoaded : SaveChangesInterceptor
    {
        private readonly TaskCompletionSource ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int arrived;
        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref arrived) == 2) ready.SetResult();
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
            return result;
        }
    }

    private sealed class BeforeSave(Func<Task> change) : SaveChangesInterceptor
    {
        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            await change();
            return result;
        }
    }
}
