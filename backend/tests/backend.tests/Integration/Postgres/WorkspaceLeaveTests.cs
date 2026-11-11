using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Npgsql;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Memberships;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class WorkspaceLeaveTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 12, 0, 0, 789, TimeSpan.Zero);
    private static readonly DateTime RevokedAt = new(2026, 11, 10, 12, 0, 0, DateTimeKind.Utc);

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var db = fixture.CreateContext();
        db.Workspaces.AddRange(Enumerable.Range(1, 5).Select(id => new Workspace { Id = id, Name = $"Workspace {id}", IsDeleted = id == 2 }));
        db.Users.AddRange(new User { Id = 1, Email = "leaving@example.test", ActiveWorkspaceId = 1 },
            new User { Id = 2, Email = "admin@example.test", ActiveWorkspaceId = 1 },
            new User { Id = 3, Email = "deleted@example.test", ActiveWorkspaceId = 1, IsDeleted = true },
            new User { Id = 4, Email = "outsider@example.test", ActiveWorkspaceId = 5 });
        db.WorkspaceUsers.AddRange(Enumerable.Range(1, 4).Select(id => new WorkspaceUser
            { UserId = 1, WorkspaceId = id, WorkspaceRole = id == 3 ? WorkspaceRole.WorkspaceAdmin : WorkspaceRole.Normal }));
        db.WorkspaceUsers.AddRange(new WorkspaceUser { UserId = 2, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
            new WorkspaceUser { UserId = 2, WorkspaceId = 3, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
            new WorkspaceUser { UserId = 3, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
            new WorkspaceUser { UserId = 4, WorkspaceId = 5, WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
        db.TokenRevocations.Add(new TokenRevocation { UserId = 1, RevokedAtUtc = RevokedAt.AddDays(-1) });
        await db.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData(999, 1)]
    [InlineData(3, 1)]
    [InlineData(4, 1)]
    [InlineData(1, 999)]
    [InlineData(1, 2)]
    public async Task MissingOrInactiveMembership_DoesNotChangeIdentityOrRevocation(int userId, int workspaceId)
    {
        var result = await Command().LeaveAsync(userId, workspaceId);
        Assert.Equal(WorkspaceLeaveStatus.NotFound, result.Status);
        Assert.Null(result.Session);
        await AssertNotLeft();
    }

    [Fact]
    public async Task OnlyActiveWorkspace_CannotBeLeftEvenWhenDeletedMembershipsRemain()
    {
        await using (var db = fixture.CreateContext())
            await db.WorkspaceUsers.Where(m => m.UserId == 1 && m.WorkspaceId >= 3).ExecuteDeleteAsync();
        var result = await Command().LeaveAsync(1, 1);
        Assert.Equal(WorkspaceLeaveStatus.Invalid, result.Status);
        Assert.Equal("Cannot leave your only active workspace", result.Error);
        await AssertNotLeft();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SoleActiveAdmin_CannotLeaveWhenOtherAdminsAreDeleted(bool deleteOtherAdmin)
    {
        await using (var db = fixture.CreateContext())
        {
            (await db.WorkspaceUsers.SingleAsync(m => m.UserId == 1 && m.WorkspaceId == 1)).WorkspaceRole = WorkspaceRole.WorkspaceAdmin;
            if (deleteOtherAdmin) (await db.Users.SingleAsync(u => u.Id == 2)).IsDeleted = true;
            else (await db.WorkspaceUsers.SingleAsync(m => m.UserId == 2 && m.WorkspaceId == 1)).WorkspaceRole = WorkspaceRole.Normal;
            await db.SaveChangesAsync();
        }
        var result = await Command().LeaveAsync(1, 1);
        Assert.Equal(WorkspaceLeaveStatus.Invalid, result.Status);
        Assert.Contains("only admin", result.Error);
        await AssertNotLeft();
    }

    [Theory]
    [InlineData(1, 3)]
    [InlineData(2, 3)]
    [InlineData(4, 4)]
    [InlineData(5, 3)]
    [InlineData(null, 3)]
    public async Task Leave_ChoosesOrRetainsAnActiveMembershipAndCommitsRevocation(int? activeId, int expectedId)
    {
        await using (var db = fixture.CreateContext())
        {
            (await db.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId = activeId;
            await db.SaveChangesAsync();
        }
        var result = await Command().LeaveAsync(1, 1);
        {
            using var committed = fixture.CreateContext();
            Assert.False(committed.WorkspaceUsers.Any(m => m.UserId == 1 && m.WorkspaceId == 1));
            Assert.Equal(expectedId, committed.Users.Single(u => u.Id == 1).ActiveWorkspaceId);
            Assert.Equal(RevokedAt, committed.TokenRevocations.Single().RevokedAtUtc);
        }
        Assert.Equal(WorkspaceLeaveStatus.Left, result.Status);
        Assert.Null(result.Error);
        Assert.Equal(expectedId, result.Session!.User.ActiveWorkspaceId);
        Assert.Equal(expectedId, result.Session.Response.WorkspaceId);
        Assert.Equal(expectedId == 3 ? WorkspaceRole.WorkspaceAdmin : WorkspaceRole.Normal, result.Session.Response.WorkspaceRole);
        Assert.Equal(new[] { 3, 4 }, result.Session.Response.Workspaces.Select(m => m.WorkspaceId));
        await using var check = fixture.CreateContext();
        Assert.Equal(new[] { 2, 3, 4 }, await check.WorkspaceUsers.Where(m => m.UserId == 1).OrderBy(m => m.WorkspaceId).Select(m => m.WorkspaceId).ToArrayAsync());
        Assert.False((await check.Users.SingleAsync(u => u.Id == 1)).IsDeleted);
    }

    [Fact]
    public async Task Administrator_CanLeaveWhenAnotherActiveAdminRemains()
    {
        await using (var db = fixture.CreateContext())
        {
            (await db.WorkspaceUsers.SingleAsync(m => m.UserId == 1 && m.WorkspaceId == 1)).WorkspaceRole = WorkspaceRole.WorkspaceAdmin;
            await db.SaveChangesAsync();
        }
        Assert.Equal(WorkspaceLeaveStatus.Left, (await Command().LeaveAsync(1, 1)).Status);
        await using var check = fixture.CreateContext();
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, (await check.WorkspaceUsers.SingleAsync(m => m.UserId == 2 && m.WorkspaceId == 1)).WorkspaceRole);
    }

    [Fact]
    public async Task CommitFailure_AfterMembershipActiveWorkspaceAndRevocationWrites_RollsBackEverything()
    {
        await using var setup = fixture.CreateContext();
        await setup.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION leave_failure() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'Workspace leave test failure'; END $$
            """);
        await setup.Database.ExecuteSqlRawAsync("""
            CREATE CONSTRAINT TRIGGER leave_failure AFTER INSERT OR UPDATE ON "TokenRevocations"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION leave_failure()
            """);
        try
        {
            var observation = new ObserveCompletedWrites();
            var logger = new Mock<ILogger<WorkspaceLeave>>(MockBehavior.Strict);
            var command = new WorkspaceLeave(Factory(observation), new Clock(), logger.Object);
            await Assert.ThrowsAsync<PostgresException>(() => command.LeaveAsync(1, 1));
            Assert.True(observation.WritesVerified);
            logger.VerifyNoOtherCalls();
            await AssertNotLeft();
        }
        finally
        {
            await setup.Database.ExecuteSqlRawAsync("DROP TRIGGER leave_failure ON \"TokenRevocations\"");
            await setup.Database.ExecuteSqlRawAsync("DROP FUNCTION leave_failure()");
        }
    }

    [Fact]
    public async Task ConcurrentExits_CannotRemoveBothRemainingActiveMemberships()
    {
        await using (var db = fixture.CreateContext())
            await db.WorkspaceUsers.Where(m => m.UserId == 1 && m.WorkspaceId == 3).ExecuteDeleteAsync();
        var command = Command(new SynchronizedSaves());
        var outcomes = await Task.WhenAll(command.LeaveAsync(1, 1), command.LeaveAsync(1, 4)).WaitAsync(TimeSpan.FromSeconds(20));
        Assert.Single(outcomes, r => r.Status == WorkspaceLeaveStatus.Left);
        Assert.Single(outcomes, r => r.Status == WorkspaceLeaveStatus.Conflict && r.Error!.Contains("Reload"));
        await using var check = fixture.CreateContext();
        var remaining = Assert.Single(await check.WorkspaceUsers.Where(m => m.UserId == 1 && !m.Workspace.IsDeleted).ToListAsync());
        Assert.Equal(remaining.WorkspaceId, (await check.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
        Assert.Equal(RevokedAt, (await check.TokenRevocations.SingleAsync()).RevokedAtUtc);
    }

    [Fact]
    public async Task ConcurrentAdministratorExits_LeaveAtLeastOneActiveAdmin()
    {
        await using (var db = fixture.CreateContext())
        {
            (await db.WorkspaceUsers.SingleAsync(m => m.UserId == 1 && m.WorkspaceId == 1)).WorkspaceRole = WorkspaceRole.WorkspaceAdmin;
            await db.SaveChangesAsync();
        }
        var command = Command(new SynchronizedSaves());
        var outcomes = await Task.WhenAll(command.LeaveAsync(1, 1), command.LeaveAsync(2, 1)).WaitAsync(TimeSpan.FromSeconds(20));
        Assert.Single(outcomes, r => r.Status == WorkspaceLeaveStatus.Left);
        Assert.Single(outcomes, r => r.Status == WorkspaceLeaveStatus.Conflict);
        await using var check = fixture.CreateContext();
        var admin = Assert.Single(await check.WorkspaceUsers.Where(m => m.WorkspaceId == 1 && m.WorkspaceRole == WorkspaceRole.WorkspaceAdmin && !m.User.IsDeleted).ToListAsync());
        var departed = admin.UserId == 1 ? 2 : 1;
        Assert.Equal(1, (await check.Users.SingleAsync(u => u.Id == admin.UserId)).ActiveWorkspaceId);
        Assert.Equal(3, (await check.Users.SingleAsync(u => u.Id == departed)).ActiveWorkspaceId);
        Assert.Equal(RevokedAt, (await check.TokenRevocations.SingleAsync(r => r.UserId == departed)).RevokedAtUtc);
    }

    [Fact]
    public async Task RoleChangedAfterValidation_RejectsTheStaleExit()
    {
        var command = Command(new BeforeMembershipSave(async () =>
        {
            await using var db = fixture.CreateContext();
            await db.WorkspaceUsers.Where(m => m.UserId == 1 && m.WorkspaceId == 1)
                .ExecuteUpdateAsync(set => set.SetProperty(m => m.WorkspaceRole, WorkspaceRole.WorkspaceAdmin));
        }));
        Assert.Equal(WorkspaceLeaveStatus.Conflict, (await command.LeaveAsync(1, 1)).Status);
        await AssertNotLeft();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Endpoint_UsesTheTransactionAndReturnsAnActiveReplacementCookie(bool staleActiveWorkspace)
    {
        if (staleActiveWorkspace)
        {
            await using var db = fixture.CreateContext();
            (await db.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId = 2;
            await db.SaveChangesAsync();
        }
        await using var factory = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, staleActiveWorkspace ? "2" : "1");
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, "1");
        var result = await client.DeleteAsync("/api/workspaces/1/membership");
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        Assert.True((await result.Content.ReadFromJsonAsync<LeaveWorkspaceResponse>())!.Success);
        var cookie = Assert.Single(result.Headers.GetValues("Set-Cookie"));
        var principal = factory.Services.GetRequiredService<ITokenService>().ValidateAppToken(cookie.Split(';')[0].Split('=', 2)[1]);
        Assert.Equal("3", principal!.FindFirst(ClaimNames.WorkspaceId)!.Value);
        Assert.Equal("WorkspaceAdmin", principal.FindFirst(ClaimNames.WorkspaceRole)!.Value);
        await using var check = fixture.CreateContext();
        Assert.False(await check.WorkspaceUsers.AnyAsync(m => m.UserId == 1 && m.WorkspaceId == 1));
        Assert.Equal(3, (await check.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
        Assert.True((await check.TokenRevocations.SingleAsync()).RevokedAtUtc > RevokedAt.AddDays(-1));
        Assert.Equal(HttpStatusCode.NotFound, (await client.DeleteAsync("/api/workspaces/1/membership")).StatusCode);
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.DeleteAsync("/api/workspaces/1/membership")).StatusCode);
    }

    private WorkspaceLeave Command(params IInterceptor[] interceptors) =>
        new(Factory(interceptors), new Clock(), NullLogger<WorkspaceLeave>.Instance);

    private IDbContextFactory<AppDbContext> Factory(params IInterceptor[] interceptors) => new TestDbContextFactory(
        new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString).AddInterceptors(interceptors).Options);

    private async Task AssertNotLeft()
    {
        await using var check = fixture.CreateContext();
        Assert.True(await check.WorkspaceUsers.AnyAsync(m => m.UserId == 1 && m.WorkspaceId == 1));
        Assert.Equal(1, (await check.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
        var revocation = Assert.Single(await check.TokenRevocations.ToListAsync());
        Assert.Equal(1, revocation.UserId);
        Assert.Equal(RevokedAt.AddDays(-1), revocation.RevokedAtUtc);
    }

    private sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }

    private sealed class ObserveCompletedWrites : DbCommandInterceptor
    {
        public bool WritesVerified { get; private set; }
        public override async ValueTask<int> NonQueryExecutedAsync(DbCommand command, CommandExecutedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.StartsWith("INSERT INTO \"TokenRevocations\"", StringComparison.Ordinal))
            {
                var db = (AppDbContext)eventData.Context!;
                Assert.False(await db.WorkspaceUsers.AnyAsync(m => m.UserId == 1 && m.WorkspaceId == 1, cancellationToken));
                Assert.Equal(3, await db.Users.Where(u => u.Id == 1).Select(u => u.ActiveWorkspaceId).SingleAsync(cancellationToken));
                Assert.Equal(RevokedAt, (await db.TokenRevocations.SingleAsync(cancellationToken)).RevokedAtUtc);
                WritesVerified = true;
            }
            return result;
        }
    }
}
