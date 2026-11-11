using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
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
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class WorkspaceAccessTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 12, 0, 0, TimeSpan.Zero);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var db = fixture.CreateContext();
        db.Workspaces.AddRange(Enumerable.Range(1, 5).Select(id => new Workspace { Id = id, Name = $"Workspace {id}", IsDeleted = id == 3 }));
        db.Users.AddRange(new User { Id = 1, Email = "owner@example.test", ActiveWorkspaceId = 1, ProviderSubjectId = "linked", AcceptedTermsAt = Now.AddDays(-1).UtcDateTime },
            new User { Id = 2, Email = "deleted@example.test", IsDeleted = true },
            new User { Id = 3, Email = "workspace-less@example.test" });
        db.WorkspaceUsers.AddRange(Enumerable.Range(1, 4).Select(id => new WorkspaceUser
        {
            WorkspaceId = id, UserId = 1, WorkspaceRole = id == 2 ? WorkspaceRole.Normal : WorkspaceRole.WorkspaceAdmin
        }));
        db.WorkspaceUsers.Add(new WorkspaceUser { WorkspaceId = 2, UserId = 2 });
        db.TokenRevocations.Add(new TokenRevocation { UserId = 1, RevokedAtUtc = Now.AddDays(-2).UtcDateTime });
        await db.SaveChangesAsync();
        await db.Database.ExecuteSqlRawAsync("""
            SELECT setval(pg_get_serial_sequence('"Workspaces"', 'Id'), (SELECT MAX("Id") FROM "Workspaces"))
            """);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData(1, 1)]
    [InlineData(3, null)]
    public async Task Creation_AddsEmptyWorkspaceAndAdminWithoutChangingSession(int userId, int? activeId)
    {
        var outcome = await Creation().CreateAsync(userId, new() { Name = "  New library  " });
        Assert.Equal(WorkspaceCreationStatus.Created, outcome.Status);
        var response = Assert.IsType<CreateWorkspaceResponse>(outcome.Workspace);
        Assert.Equal("New library", response.WorkspaceName);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, response.WorkspaceRole);
        Assert.False(response.HasCompletedWelcome);
        await using var check = fixture.CreateContext();
        var workspace = await check.Workspaces.SingleAsync(w => w.Id == response.WorkspaceId);
        Assert.Equal("New library", workspace.Name);
        Assert.False(workspace.HasCompletedWelcome);
        Assert.Equal(Now.UtcDateTime, workspace.CreatedAt);
        Assert.Null(workspace.Slug);
        var membership = await check.WorkspaceUsers.SingleAsync(m => m.WorkspaceId == workspace.Id);
        Assert.Equal(userId, membership.UserId);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, membership.WorkspaceRole);
        Assert.Equal(Now.UtcDateTime, membership.CreatedAt);
        Assert.Equal(activeId, (await check.Users.SingleAsync(u => u.Id == userId)).ActiveWorkspaceId);
        Assert.Empty(await check.Collections.ToListAsync());
        Assert.Equal(Now.AddDays(-2).UtcDateTime, (await check.TokenRevocations.SingleAsync()).RevokedAtUtc);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(999)]
    public async Task Creation_RequiresAnActiveAccount(int userId)
    {
        Assert.Equal(WorkspaceCreationStatus.Forbidden, (await Creation().CreateAsync(userId, new() { Name = "Library" })).Status);
        await AssertNoWorkspaceCreated();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public async Task Creation_RejectsMissingName(string? name)
    {
        Assert.Equal(WorkspaceCreationStatus.Invalid, (await Creation().CreateAsync(1, new() { Name = name! })).Status);
        await AssertNoWorkspaceCreated();
    }

    [Fact]
    public async Task Creation_ValidatesNameLengthAtTheBoundary()
    {
        Assert.Equal(WorkspaceCreationStatus.Invalid, (await Creation().CreateAsync(1, new() { Name = new string('a', 201) })).Status);
        await AssertNoWorkspaceCreated();
        Assert.Equal(WorkspaceCreationStatus.Created, (await Creation().CreateAsync(1, new() { Name = new string('a', 200) })).Status);
    }

    [Fact]
    public async Task Creation_WhenAccountDisappearsDuringTheWrite_ReturnsConflictWithoutAnOrphanWorkspace()
    {
        var remove = new BeforeMembershipSave(async () =>
        {
            await using var db = fixture.CreateContext();
            await db.Users.Where(u => u.Id == 3).ExecuteDeleteAsync();
        });
        var outcome = await Creation(remove).CreateAsync(3, new() { Name = "Library" });
        Assert.Equal(WorkspaceCreationStatus.Conflict, outcome.Status);
        Assert.Contains("Reload", outcome.Error);
        await AssertNoWorkspaceCreated();
    }

    [Theory]
    [InlineData(999, 2)]
    [InlineData(2, 2)]
    [InlineData(3, 2)]
    [InlineData(1, 5)]
    [InlineData(1, 999)]
    [InlineData(1, 3)]
    public async Task Switch_RequiresAnActiveAccountAndActiveTargetMembership(int userId, int workspaceId)
    {
        var outcome = await Switching().SwitchAsync(userId, workspaceId);
        Assert.Equal(WorkspaceSwitchStatus.Forbidden, outcome.Status);
        Assert.Null(outcome.Session);
        await AssertOriginalSession();
    }

    [Theory]
    [InlineData(2, WorkspaceRole.Normal)]
    [InlineData(4, WorkspaceRole.WorkspaceAdmin)]
    public async Task Switch_CommitsActiveWorkspaceAndReturnsItsCurrentRole(int workspaceId, WorkspaceRole role)
    {
        var outcome = await Switching().SwitchAsync(1, workspaceId);
        Assert.Equal(WorkspaceSwitchStatus.Switched, outcome.Status);
        var session = Assert.IsType<CurrentUserSession>(outcome.Session);
        Assert.Equal(workspaceId, session.User.ActiveWorkspaceId);
        Assert.Equal(workspaceId, session.Response.WorkspaceId);
        Assert.Equal(role, session.Response.WorkspaceRole);
        Assert.Equal($"Workspace {workspaceId}", session.Response.WorkspaceName);
        Assert.Equal(new[] { 1, 2, 4 }, session.Response.Workspaces.Select(w => w.WorkspaceId));
        await using var check = fixture.CreateContext();
        var user = await check.Users.SingleAsync(u => u.Id == 1);
        Assert.Equal(workspaceId, user.ActiveWorkspaceId);
        Assert.Equal("linked", user.ProviderSubjectId);
        Assert.Equal(Now.AddDays(-1).UtcDateTime, user.AcceptedTermsAt);
        Assert.Equal(4, await check.WorkspaceUsers.CountAsync(m => m.UserId == 1));
        Assert.Equal(Now.AddDays(-2).UtcDateTime, (await check.TokenRevocations.SingleAsync()).RevokedAtUtc);
    }

    [Fact]
    public async Task SwitchToCurrentWorkspace_DoesNotWriteAndStillReturnsCurrentSession()
    {
        var failOnWrite = new BeforeMembershipSave(() => throw new InvalidOperationException("No write expected"));
        var outcome = await Switching(failOnWrite).SwitchAsync(1, 1);
        Assert.Equal(WorkspaceSwitchStatus.Switched, outcome.Status);
        Assert.Equal(1, outcome.Session!.Response.WorkspaceId);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, outcome.Session.Response.WorkspaceRole);
        await AssertOriginalSession();
    }

    [Fact]
    public async Task ConcurrentSwitches_CommitOneAuthoritativeSessionAndReportTheOtherAsConflict()
    {
        var commands = Switching(new SynchronizedSaves());
        var outcomes = await Task.WhenAll(commands.SwitchAsync(1, 2), commands.SwitchAsync(1, 4)).WaitAsync(TimeSpan.FromSeconds(20));
        var committed = Assert.Single(outcomes, r => r.Status == WorkspaceSwitchStatus.Switched);
        var rejected = Assert.Single(outcomes, r => r.Status == WorkspaceSwitchStatus.Conflict);
        Assert.Null(rejected.Session);
        Assert.Contains("Reload", rejected.Error);
        await using var check = fixture.CreateContext();
        Assert.Equal(committed.Session!.Response.WorkspaceId, (await check.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
    }

    [Fact]
    public async Task Switch_DoesNotOverwriteConcurrentActiveWorkspaceChanges()
    {
        var change = new BeforeMembershipSave(async () =>
        {
            await using var db = fixture.CreateContext();
            await db.Users.Where(u => u.Id == 1).ExecuteUpdateAsync(s => s.SetProperty(u => u.ActiveWorkspaceId, 4));
        });
        var outcome = await Switching(change).SwitchAsync(1, 2);
        Assert.Equal(WorkspaceSwitchStatus.Conflict, outcome.Status);
        Assert.Null(outcome.Session);
        await using var check = fixture.CreateContext();
        Assert.Equal(4, (await check.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Switch_ConflictsWithMembershipChangesAfterItsSnapshot(bool remove)
    {
        await using (var setup = fixture.CreateContext())
        {
            setup.Users.Add(new User { Id = 4, Email = "target-admin@example.test", ActiveWorkspaceId = 2 });
            setup.WorkspaceUsers.Add(new WorkspaceUser { UserId = 4, WorkspaceId = 2, WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
            await setup.SaveChangesAsync();
        }
        var change = new BeforeMembershipSave(async () =>
        {
            var membership = new TeamMembershipChanges(Factory(), new Clock(), NullLogger<TeamMembershipChanges>.Instance);
            var edited = remove ? await membership.RemoveAsync(4, 2, 1) : await membership.ChangeRoleAsync(4, 2, 1, WorkspaceRole.WorkspaceAdmin);
            Assert.Equal(TeamMembershipStatus.Changed, edited.Status);
        });
        var outcome = await Switching(change).SwitchAsync(1, 2);
        Assert.Equal(WorkspaceSwitchStatus.Conflict, outcome.Status);
        Assert.Null(outcome.Session);
        await using var check = fixture.CreateContext();
        Assert.Equal(1, (await check.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
        var target = await check.WorkspaceUsers.SingleOrDefaultAsync(m => m.UserId == 1 && m.WorkspaceId == 2);
        if (remove) Assert.Null(target);
        else Assert.Equal(WorkspaceRole.WorkspaceAdmin, target!.WorkspaceRole);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DeferredCommitFailure_RollsBackCompletedWritesAndDoesNotLogSuccess(bool create)
    {
        await using var setup = fixture.CreateContext();
        await setup.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION workspace_access_failure() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'Workspace access test failure'; END $$
            """);
        await setup.Database.ExecuteSqlRawAsync(create ? """
            CREATE CONSTRAINT TRIGGER workspace_access_failure AFTER INSERT ON "WorkspaceUsers"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION workspace_access_failure()
            """ : """
            CREATE CONSTRAINT TRIGGER workspace_access_failure AFTER UPDATE ON "Users"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION workspace_access_failure()
            """);
        try
        {
            var observer = new ObserveWrite(create);
            var createLog = new Mock<ILogger<WorkspaceCreation>>(MockBehavior.Strict);
            var switchLog = new Mock<ILogger<WorkspaceSwitch>>(MockBehavior.Strict);
            if (create)
                await Assert.ThrowsAsync<PostgresException>(() => new WorkspaceCreation(Factory(observer), new Clock(), createLog.Object).CreateAsync(1, new() { Name = "Library" }));
            else
                await Assert.ThrowsAsync<PostgresException>(() => new WorkspaceSwitch(Factory(observer), switchLog.Object).SwitchAsync(1, 2));
            Assert.True(observer.Verified);
            createLog.VerifyNoOtherCalls();
            switchLog.VerifyNoOtherCalls();
            await AssertNoWorkspaceCreated();
            await AssertOriginalSession();
        }
        finally
        {
            await setup.Database.ExecuteSqlRawAsync(create
                ? "DROP TRIGGER workspace_access_failure ON \"WorkspaceUsers\""
                : "DROP TRIGGER workspace_access_failure ON \"Users\"");
            await setup.Database.ExecuteSqlRawAsync("DROP FUNCTION workspace_access_failure()");
        }
    }

    [Fact]
    public async Task Endpoints_AllowRecoveryFromInactiveWorkspaceAndIssueOnlyTheSwitchCookie()
    {
        await using (var db = fixture.CreateContext())
            await db.Users.Where(u => u.Id == 1).ExecuteUpdateAsync(s => s.SetProperty(u => u.ActiveWorkspaceId, 3));
        await using var factory = new MembershipWebApplicationFactory(fixture.ConnectionString);
        Assert.IsType<WorkspaceCreation>(factory.Services.GetRequiredService<IWorkspaceCreation>());
        Assert.IsType<WorkspaceSwitch>(factory.Services.GetRequiredService<IWorkspaceSwitch>());
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, "1");
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, "3");
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceRoleHeader, "WorkspaceAdmin");
        var created = await client.PostAsJsonAsync("/api/workspaces", new CreateWorkspaceRequest { Name = "HTTP workspace" });
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        Assert.False(created.Headers.Contains("Set-Cookie"));
        var workspace = await created.Content.ReadFromJsonAsync<CreateWorkspaceResponse>(Json);
        Assert.Equal("HTTP workspace", workspace!.WorkspaceName);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, workspace.WorkspaceRole);
        Assert.False(workspace.HasCompletedWelcome);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/workspaces", new CreateWorkspaceRequest { Name = " " })).StatusCode);

        var switched = await client.PostAsync("/api/workspaces/2/switch", null);
        Assert.Equal(HttpStatusCode.OK, switched.StatusCode);
        Assert.True((await switched.Content.ReadFromJsonAsync<SwitchWorkspaceResponse>())!.Success);
        var cookie = Assert.Single(switched.Headers.GetValues("Set-Cookie"));
        var principal = factory.Services.GetRequiredService<ITokenService>().ValidateAppToken(cookie.Split(';')[0].Split('=', 2)[1]);
        Assert.Equal("2", principal!.FindFirst(ClaimNames.WorkspaceId)!.Value);
        Assert.Equal("Normal", principal.FindFirst(ClaimNames.WorkspaceRole)!.Value);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsync("/api/workspaces/3/switch", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsync("/api/workspaces/5/switch", null)).StatusCode);
        await using var check = fixture.CreateContext();
        Assert.Equal(2, (await check.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsync("/api/workspaces/2/switch", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync("/api/workspaces", new CreateWorkspaceRequest { Name = "Unauthorized" })).StatusCode);
    }

    private WorkspaceCreation Creation(params IInterceptor[] interceptors) => new(Factory(interceptors), new Clock(), NullLogger<WorkspaceCreation>.Instance);
    private WorkspaceSwitch Switching(params IInterceptor[] interceptors) => new(Factory(interceptors), NullLogger<WorkspaceSwitch>.Instance);
    private IDbContextFactory<AppDbContext> Factory(params IInterceptor[] interceptors) => new TestDbContextFactory(
        new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString).AddInterceptors(interceptors).Options);
    private async Task AssertNoWorkspaceCreated()
    {
        await using var check = fixture.CreateContext();
        Assert.Equal(5, await check.Workspaces.CountAsync());
        Assert.Equal(5, await check.WorkspaceUsers.CountAsync());
    }
    private async Task AssertOriginalSession()
    {
        await using var check = fixture.CreateContext();
        var user = await check.Users.SingleAsync(u => u.Id == 1);
        Assert.Equal(1, user.ActiveWorkspaceId);
        Assert.Equal("linked", user.ProviderSubjectId);
        Assert.Equal(Now.AddDays(-1).UtcDateTime, user.AcceptedTermsAt);
        Assert.Equal(Now.AddDays(-2).UtcDateTime, (await check.TokenRevocations.SingleAsync()).RevokedAtUtc);
    }
    private sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class ObserveWrite(bool create) : SaveChangesInterceptor
    {
        public bool Verified { get; private set; }
        public override async ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            var db = (AppDbContext)eventData.Context!;
            if (create)
            {
                var workspace = await db.Workspaces.SingleAsync(w => w.Name == "Library", cancellationToken);
                Assert.True(await db.WorkspaceUsers.AnyAsync(m => m.WorkspaceId == workspace.Id && m.UserId == 1 && m.WorkspaceRole == WorkspaceRole.WorkspaceAdmin, cancellationToken));
            }
            else Assert.Equal(2, (await db.Users.SingleAsync(u => u.Id == 1, cancellationToken)).ActiveWorkspaceId);
            Verified = true;
            return result;
        }
    }
}
