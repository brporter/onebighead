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
public class TeamMembershipChangesTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 12, 0, 0, 789, TimeSpan.Zero);
    private static readonly DateTime RevokedAt = new(2026, 11, 10, 12, 0, 0, DateTimeKind.Utc);

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var db = fixture.CreateContext();
        db.Workspaces.AddRange(Enumerable.Range(1, 4).Select(id => new Workspace { Id = id, Name = $"Workspace {id}", IsDeleted = id == 3 }));
        db.Users.AddRange(new User { Id = 1, Email = "admin@example.test", ActiveWorkspaceId = 1 },
            new User { Id = 2, Email = "member@example.test", ActiveWorkspaceId = 1, ProviderSubjectId = "linked-member", IsSystemAdministrator = true, AcceptedTermsAt = RevokedAt.AddDays(-10) },
            new User { Id = 3, Email = "other-admin@example.test", ActiveWorkspaceId = 1 },
            new User { Id = 4, Email = "deleted@example.test", ActiveWorkspaceId = 1, IsDeleted = true },
            new User { Id = 5, Email = "outsider@example.test", ActiveWorkspaceId = 2 });
        foreach (var id in new[] { 1, 2, 3 })
            db.WorkspaceUsers.AddRange(new WorkspaceUser { UserId = id, WorkspaceId = 1, WorkspaceRole = id == 2 ? WorkspaceRole.Normal : WorkspaceRole.WorkspaceAdmin },
                new WorkspaceUser { UserId = id, WorkspaceId = 2, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
                new WorkspaceUser { UserId = id, WorkspaceId = 3, WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
        db.WorkspaceUsers.AddRange(new WorkspaceUser { UserId = 4, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
            new WorkspaceUser { UserId = 5, WorkspaceId = 2 });
        db.TokenRevocations.Add(new TokenRevocation { UserId = 2, RevokedAtUtc = RevokedAt.AddDays(-1) });
        db.SupportRequests.Add(new SupportRequest { Id = 1, UserId = 2, Email = "member@example.test", Subject = "History", Description = "Keep this account history" });
        await db.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData(999, 1, 2)]
    [InlineData(4, 1, 2)]
    [InlineData(5, 1, 2)]
    [InlineData(2, 1, 1)]
    [InlineData(1, 999, 2)]
    [InlineData(1, 3, 2)]
    public async Task CurrentAdministratorRequired_ForBothOperations(int actor, int workspace, int target)
    {
        Assert.Equal(TeamMembershipStatus.Forbidden, (await Commands().ChangeRoleAsync(actor, workspace, target, WorkspaceRole.WorkspaceAdmin)).Status);
        Assert.Equal(TeamMembershipStatus.Forbidden, (await Commands().RemoveAsync(actor, workspace, target)).Status);
        await AssertMemberUnchanged();
    }

    [Fact]
    public async Task SelfEditsAndMissingTargets_DoNotMutateOrRevoke()
    {
        var commands = Commands();
        Assert.Equal(TeamMembershipStatus.Invalid, (await commands.ChangeRoleAsync(1, 1, 1, WorkspaceRole.Normal)).Status);
        Assert.Equal(TeamMembershipStatus.Invalid, (await commands.RemoveAsync(1, 1, 1)).Status);
        foreach (var id in new[] { 5, 999 })
        {
            Assert.Equal(TeamMembershipStatus.NotFound, (await commands.ChangeRoleAsync(1, 1, id, WorkspaceRole.Normal)).Status);
            Assert.Equal(TeamMembershipStatus.NotFound, (await commands.RemoveAsync(1, 1, id)).Status);
        }
        Assert.Equal(TeamMembershipStatus.Invalid, (await commands.ChangeRoleAsync(1, 1, 2, (WorkspaceRole)99)).Status);
        Assert.Equal(TeamMembershipStatus.Invalid, (await commands.ChangeRoleAsync(1, 1, 4, WorkspaceRole.Normal)).Status);
        await AssertMemberUnchanged();
    }

    [Fact]
    public async Task SameRole_IsANoOpAndPreservesNewerSessions()
    {
        Assert.Equal(TeamMembershipStatus.Changed, (await Commands().ChangeRoleAsync(1, 1, 2, WorkspaceRole.Normal)).Status);
        await AssertMemberUnchanged();
    }

    [Theory]
    [InlineData(2, WorkspaceRole.WorkspaceAdmin)]
    [InlineData(3, WorkspaceRole.Normal)]
    public async Task RoleChange_CommitsRoleAndRevocationTogether(int id, WorkspaceRole role)
    {
        Assert.Equal(TeamMembershipStatus.Changed, (await Commands().ChangeRoleAsync(1, 1, id, role)).Status);
        {
            using var committed = fixture.CreateContext();
            Assert.Equal(role, committed.WorkspaceUsers.Single(m => m.UserId == id && m.WorkspaceId == 1).WorkspaceRole);
            Assert.Equal(RevokedAt, committed.TokenRevocations.Single(r => r.UserId == id).RevokedAtUtc);
        }
        await using var check = fixture.CreateContext();
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, (await check.WorkspaceUsers.SingleAsync(m => m.UserId == id && m.WorkspaceId == 2)).WorkspaceRole);
        Assert.Equal(1, (await check.Users.SingleAsync(u => u.Id == id)).ActiveWorkspaceId);
    }

    [Theory]
    [InlineData(1, 2, 2)]
    [InlineData(2, 2, 2)]
    [InlineData(3, 2, 2)]
    [InlineData(4, 2, 2)]
    [InlineData(null, 2, 2)]
    [InlineData(1, 1, null)]
    [InlineData(1, 0, null)]
    public async Task Removal_PreservesAccountAndHistoryAndSelectsValidActiveWorkspace(int? activeId, int remainingMode, int? expectedId)
    {
        await using (var db = fixture.CreateContext())
        {
            (await db.Users.SingleAsync(u => u.Id == 2)).ActiveWorkspaceId = activeId;
            if (remainingMode < 2) db.WorkspaceUsers.RemoveRange(await db.WorkspaceUsers.Where(m => m.UserId == 2 && m.WorkspaceId == 2).ToListAsync());
            if (remainingMode == 0) db.WorkspaceUsers.RemoveRange(await db.WorkspaceUsers.Where(m => m.UserId == 2 && m.WorkspaceId == 3).ToListAsync());
            await db.SaveChangesAsync();
        }
        Assert.Equal(TeamMembershipStatus.Changed, (await Commands().RemoveAsync(1, 1, 2)).Status);
        {
            using var committed = fixture.CreateContext();
            Assert.False(committed.WorkspaceUsers.Any(m => m.UserId == 2 && m.WorkspaceId == 1));
            Assert.Equal(expectedId, committed.Users.Single(u => u.Id == 2).ActiveWorkspaceId);
            Assert.Equal(RevokedAt, committed.TokenRevocations.Single().RevokedAtUtc);
        }
        await using var check = fixture.CreateContext();
        var account = await check.Users.SingleAsync(u => u.Id == 2);
        Assert.False(account.IsDeleted);
        Assert.True(account.IsSystemAdministrator);
        Assert.Equal("linked-member", account.ProviderSubjectId);
        Assert.Equal(RevokedAt.AddDays(-10), account.AcceptedTermsAt);
        Assert.Equal(2, (await check.SupportRequests.SingleAsync()).UserId);
        Assert.Equal(remainingMode, await check.WorkspaceUsers.CountAsync(m => m.UserId == 2));
    }

    [Fact]
    public async Task DeletedAccountMembership_CanBeRemovedWithoutRestoringOrDeletingAccount()
    {
        Assert.Equal(TeamMembershipStatus.Changed, (await Commands().RemoveAsync(1, 1, 4)).Status);
        await using var check = fixture.CreateContext();
        var user = await check.Users.SingleAsync(u => u.Id == 4);
        Assert.True(user.IsDeleted);
        Assert.Null(user.ActiveWorkspaceId);
        Assert.False(await check.WorkspaceUsers.AnyAsync(m => m.UserId == 4));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CommitFailure_RollsBackMembershipIdentityAndRevocation(bool remove)
    {
        await using var setup = fixture.CreateContext();
        await setup.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION team_failure() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'Team membership test failure'; END $$
            """);
        await setup.Database.ExecuteSqlRawAsync("""
            CREATE CONSTRAINT TRIGGER team_failure AFTER INSERT OR UPDATE ON "TokenRevocations"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION team_failure()
            """);
        try
        {
            var observer = new ObserveWrites(remove);
            var logger = new Mock<ILogger<TeamMembershipChanges>>(MockBehavior.Strict);
            var commands = new TeamMembershipChanges(Factory(observer), new Clock(), logger.Object);
            await Assert.ThrowsAsync<PostgresException>(() => Edit(commands, remove, 1, 2));
            Assert.True(observer.WritesVerified);
            logger.VerifyNoOtherCalls();
            await AssertMemberUnchanged();
        }
        finally
        {
            await setup.Database.ExecuteSqlRawAsync("DROP TRIGGER team_failure ON \"TokenRevocations\"");
            await setup.Database.ExecuteSqlRawAsync("DROP FUNCTION team_failure()");
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task CompetingAdministratorEdits_CannotRemoveEveryActiveAdmin(bool firstRemoves, bool secondRemoves)
    {
        var commands = Commands(new SynchronizedSaves());
        var outcomes = await Task.WhenAll(
            Edit(commands, firstRemoves, 1, 3, WorkspaceRole.Normal),
            Edit(commands, secondRemoves, 3, 1, WorkspaceRole.Normal)).WaitAsync(TimeSpan.FromSeconds(20));
        Assert.Single(outcomes, r => r.Status == TeamMembershipStatus.Changed);
        Assert.Single(outcomes, r => r.Status == TeamMembershipStatus.Conflict && r.Error!.Contains("Reload"));
        await using var check = fixture.CreateContext();
        Assert.Single(await check.WorkspaceUsers.Where(m => m.WorkspaceId == 1 && m.WorkspaceRole == WorkspaceRole.WorkspaceAdmin && !m.User.IsDeleted).ToListAsync());
        Assert.Equal(2, await check.TokenRevocations.CountAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Endpoint_UsesCurrentDatabaseRoleAndRejectsStaleClaims(bool remove)
    {
        await using var factory = new MembershipWebApplicationFactory(fixture.ConnectionString);
        Assert.Same(factory.Services.GetRequiredService<ITeamRoleChanges>(), factory.Services.GetRequiredService<ITeamMemberRemoval>());
        using var current = Client(factory, 1, "Normal"); // Current DB admin, old non-admin claim.
        Assert.Equal(HttpStatusCode.NoContent, (await Request(current, remove, 2)).StatusCode);
        await using (var check = fixture.CreateContext())
        {
            Assert.Equal(RevokedAt.AddDays(-10), (await check.Users.SingleAsync(u => u.Id == 2)).AcceptedTermsAt);
            Assert.True((await check.TokenRevocations.SingleAsync()).RevokedAtUtc > RevokedAt.AddDays(-1));
            if (remove) Assert.False(await check.WorkspaceUsers.AnyAsync(m => m.UserId == 2 && m.WorkspaceId == 1));
            else Assert.Equal(WorkspaceRole.WorkspaceAdmin, (await check.WorkspaceUsers.SingleAsync(m => m.UserId == 2 && m.WorkspaceId == 1)).WorkspaceRole);
            (await check.WorkspaceUsers.SingleAsync(m => m.UserId == 1 && m.WorkspaceId == 1)).WorkspaceRole = WorkspaceRole.Normal;
            await check.SaveChangesAsync();
        }
        using var stale = Client(factory, 1, "WorkspaceAdmin");
        Assert.Equal(HttpStatusCode.Forbidden, (await Request(stale, remove, 3)).StatusCode);
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await Request(anonymous, remove, 3)).StatusCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Endpoint_RejectsSelfAndMissingTarget(bool remove)
    {
        await using var factory = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var client = Client(factory, 1, "WorkspaceAdmin");
        Assert.Equal(HttpStatusCode.BadRequest, (await Request(client, remove, 1)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Request(client, remove, 999)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Request(client, remove, 5)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PutAsJsonAsync("/api/users/2/role", new { role = 99 })).StatusCode);
        await AssertMemberUnchanged();
    }

    [Fact]
    public async Task RemovingLegacyPendingMember_PreservesTheUnclaimedAccount()
    {
        const string email = "pending-invitation@example.test";
        const int userId = 99;
        await using (var setup = fixture.CreateContext())
        {
            setup.WorkspaceUsers.Add(new WorkspaceUser { WorkspaceId = 1,
                User = new User { Id = userId, Email = email, ActiveWorkspaceId = 1 } });
            await setup.SaveChangesAsync();
        }
        await using var factory = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var client = Client(factory, 1, "WorkspaceAdmin");
        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync($"/api/users/{userId}")).StatusCode);
        using var members = await System.Text.Json.JsonDocument.ParseAsync(await (await client.GetAsync("/api/users")).Content.ReadAsStreamAsync());
        Assert.DoesNotContain(members.RootElement.EnumerateArray(), m => m.GetProperty("userId").GetInt32() == userId);
        await using var check = fixture.CreateContext();
        var account = await check.Users.SingleAsync(u => u.Id == userId);
        Assert.Equal(email, account.Email);
        Assert.Null(account.ActiveWorkspaceId);
        Assert.Null(account.ProviderSubjectId);
        Assert.Null(account.AcceptedTermsAt);
        Assert.False(await check.WorkspaceUsers.AnyAsync(m => m.UserId == userId));
        Assert.True(await check.TokenRevocations.AnyAsync(r => r.UserId == userId));
    }

    private static HttpClient Client(MembershipWebApplicationFactory factory, int actor, string role)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, "1");
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, actor.ToString());
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceRoleHeader, role);
        return client;
    }

    private static Task<HttpResponseMessage> Request(HttpClient client, bool remove, int target) => remove
        ? client.DeleteAsync($"/api/users/{target}")
        : client.PutAsJsonAsync($"/api/users/{target}/role", new UpdateUserRoleRequest { Role = WorkspaceRole.WorkspaceAdmin });
    private static Task<TeamMembershipResult> Edit(TeamMembershipChanges commands, bool remove, int actor, int target, WorkspaceRole role = WorkspaceRole.WorkspaceAdmin) => remove
        ? commands.RemoveAsync(actor, 1, target) : commands.ChangeRoleAsync(actor, 1, target, role);
    private TeamMembershipChanges Commands(params IInterceptor[] interceptors) => new(Factory(interceptors), new Clock(), NullLogger<TeamMembershipChanges>.Instance);
    private IDbContextFactory<AppDbContext> Factory(params IInterceptor[] interceptors) => new TestDbContextFactory(
        new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString).AddInterceptors(interceptors).Options);

    private async Task AssertMemberUnchanged()
    {
        await using var check = fixture.CreateContext();
        Assert.Equal(WorkspaceRole.Normal, (await check.WorkspaceUsers.SingleAsync(m => m.UserId == 2 && m.WorkspaceId == 1)).WorkspaceRole);
        Assert.Equal(1, (await check.Users.SingleAsync(u => u.Id == 2)).ActiveWorkspaceId);
        Assert.Equal(2, (await check.SupportRequests.SingleAsync()).UserId);
        Assert.Equal(RevokedAt.AddDays(-1), (await check.TokenRevocations.SingleAsync()).RevokedAtUtc);
    }

    private sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class ObserveWrites(bool remove) : DbCommandInterceptor
    {
        public bool WritesVerified { get; private set; }
        public override async ValueTask<int> NonQueryExecutedAsync(DbCommand command, CommandExecutedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.StartsWith("INSERT INTO \"TokenRevocations\"", StringComparison.Ordinal))
            {
                var db = (AppDbContext)eventData.Context!;
                if (remove)
                {
                    Assert.False(await db.WorkspaceUsers.AnyAsync(m => m.UserId == 2 && m.WorkspaceId == 1, cancellationToken));
                    Assert.Equal(2, await db.Users.Where(u => u.Id == 2).Select(u => u.ActiveWorkspaceId).SingleAsync(cancellationToken));
                }
                else Assert.Equal(WorkspaceRole.WorkspaceAdmin, await db.WorkspaceUsers.Where(m => m.UserId == 2 && m.WorkspaceId == 1).Select(m => m.WorkspaceRole).SingleAsync(cancellationToken));
                Assert.Equal(RevokedAt, (await db.TokenRevocations.SingleAsync(cancellationToken)).RevokedAtUtc);
                WritesVerified = true;
            }
            return result;
        }
    }
}
