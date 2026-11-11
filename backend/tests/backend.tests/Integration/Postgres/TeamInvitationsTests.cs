using System.Data.Common;
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
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Memberships;
using OneBigHead.Server.Services.Invitations;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public partial class TeamInvitationsTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 12, 0, 0, TimeSpan.Zero);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private const string NewEmail = "invited@example.test";
    private const string ExistingEmail = "existing@example.test";

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var db = fixture.CreateContext();
        db.Workspaces.AddRange(Enumerable.Range(1, 3).Select(id => new Workspace { Id = id, Name = $"Workspace {id}", IsDeleted = id == 3 }));
        db.Users.AddRange(new User { Id = 1, Email = "admin@example.test", ActiveWorkspaceId = 1 },
            new User { Id = 2, Email = "member@example.test", ActiveWorkspaceId = 1 },
            new User { Id = 3, Email = ExistingEmail, ActiveWorkspaceId = 2, IdentityProvider = IdentityProvider.Google,
                ProviderSubjectId = "linked", IsSystemAdministrator = true, AcceptedTermsAt = Now.AddDays(-20).UtcDateTime, CreatedAt = Now.AddDays(-30).UtcDateTime },
            new User { Id = 4, Email = "deleted@example.test", ActiveWorkspaceId = 2, IsDeleted = true, DeletedAt = Now.AddDays(-2).UtcDateTime },
            new User { Id = 5, Email = "second-admin@example.test", ActiveWorkspaceId = 1 });
        db.WorkspaceUsers.AddRange(new WorkspaceUser { UserId = 1, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.WorkspaceAdmin, CreatedAt = Now.AddDays(-3).UtcDateTime },
            new WorkspaceUser { UserId = 5, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.WorkspaceAdmin, CreatedAt = Now.AddDays(-3).UtcDateTime },
            new WorkspaceUser { UserId = 2, WorkspaceId = 1, CreatedAt = Now.AddDays(-2).UtcDateTime },
            new WorkspaceUser { UserId = 1, WorkspaceId = 2, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
            new WorkspaceUser { UserId = 1, WorkspaceId = 3, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
            new WorkspaceUser { UserId = 3, WorkspaceId = 2 },
            new WorkspaceUser { UserId = 4, WorkspaceId = 2, WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
        db.TokenRevocations.Add(new TokenRevocation { UserId = 3, RevokedAtUtc = Now.AddDays(-1).UtcDateTime });
        await db.SaveChangesAsync();
        await db.Database.ExecuteSqlRawAsync("""
            SELECT setval(pg_get_serial_sequence('"Users"', 'Id'), (SELECT MAX("Id") FROM "Users"))
            """);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData(999, 1)]
    [InlineData(4, 2)]
    [InlineData(3, 1)]
    [InlineData(2, 1)]
    [InlineData(1, 999)]
    [InlineData(1, 3)]
    public async Task CurrentAdministratorRequired_ForListingAndInvitations(int actor, int workspace)
    {
        Assert.Null(await new TeamDirectory(Factory()).ReadAsync(actor, workspace));
        Assert.Equal(TeamInvitationStatus.Forbidden, (await Invitations().InviteAsync(actor, workspace, Request())).Status);
        await AssertNoInvitation();
    }

    [Fact]
    public async Task Directory_UsesOneSnapshotAndReturnsOnlyCurrentWorkspaceInStableOrder()
    {
        var reads = new CountReads();
        var team = await new TeamDirectory(Factory(reads)).ReadAsync(1, 1);
        Assert.NotNull(team);
        Assert.Equal(new[] { 1, 5, 2 }, team.Select(m => m.UserId));
        Assert.Equal(new[] { WorkspaceRole.WorkspaceAdmin, WorkspaceRole.WorkspaceAdmin, WorkspaceRole.Normal }, team.Select(m => m.WorkspaceRole));
        Assert.Equal("admin@example.test", team[0].Email);
        Assert.Equal(Now.AddDays(-3).UtcDateTime, team[0].CreatedAt);
        Assert.All(team, m => Assert.False(m.IsLinked));
        Assert.Equal(1, reads.Count);
    }

    [Theory]
    [InlineData(WorkspaceRole.Normal)]
    [InlineData(WorkspaceRole.WorkspaceAdmin)]
    public async Task CreateLink_DoesNotGrantMembershipOrClaimAnyEmailMatch(WorkspaceRole role)
    {
        var created = (await Invitations().InviteAsync(1, 1, Request(ExistingEmail.ToUpperInvariant(), role))).Invitation!;
        Assert.Equal(ExistingEmail, created.Invitation.Email);
        Assert.Equal(role, created.Invitation.Role);
        Assert.Equal(Now.UtcDateTime, created.Invitation.CreatedAt);
        Assert.Equal(Now.AddDays(7).UtcDateTime, created.Invitation.ExpiresAt);
        Assert.Equal(64, created.Token.Length);
        await using var check = fixture.CreateContext();
        var stored = await check.WorkspaceInvitations.SingleAsync();
        Assert.NotEqual(created.Token, stored.TokenHash);
        Assert.Equal(5, await check.Users.CountAsync());
        Assert.Equal(7, await check.WorkspaceUsers.CountAsync());
        var existing = await check.Users.SingleAsync(user => user.Id == 3);
        Assert.Equal(2, existing.ActiveWorkspaceId);
        Assert.True(existing.IsSystemAdministrator);
        Assert.Equal("linked", existing.ProviderSubjectId);
        Assert.DoesNotContain("TokenHash", JsonSerializer.Serialize(stored));
        var read = await new InvitationDirectory(Factory()).ReadAsync(1, 1);
        Assert.Equal(created.Invitation, Assert.Single(read!));
        Assert.Empty((await new InvitationDirectory(Factory()).ReadAsync(1, 2))!);
        Assert.Null(await new InvitationDirectory(Factory()).ReadAsync(2, 1));
        var preview = await Preview().ReadAsync(Access(created));
        Assert.Equal("Workspace 1", preview!.WorkspaceName);
        Assert.Equal(ExistingEmail, preview.Email);
        Assert.Equal(role, preview.Role);
    }

    [Fact]
    public async Task ReplacementLink_ExpiresThePreviousTokenAndRetainsOnePendingInvitation()
    {
        var first = (await Invitations().InviteAsync(1, 1, Request())).Invitation!;
        var second = (await Invitations().InviteAsync(1, 1, Request(role: WorkspaceRole.WorkspaceAdmin))).Invitation!;
        Assert.Equal(first.Invitation.InvitationId, second.Invitation.InvitationId);
        Assert.NotEqual(first.Token, second.Token);
        Assert.Null(await Preview().ReadAsync(Access(first)));
        Assert.NotNull(await Preview().ReadAsync(Access(second)));
        var reads = new CountReads();
        var list = await new InvitationDirectory(Factory(reads)).ReadAsync(1, 1);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, Assert.Single(list!).Role);
        Assert.Equal(1, reads.Count);
    }

    [Fact]
    public async Task ConcurrentCreation_ProducesOnePendingGrantAndOneReviewableConflict()
    {
        var commands = Invitations(new SynchronizedSaves());
        var results = await Task.WhenAll(commands.InviteAsync(1, 1, Request()), commands.InviteAsync(1, 1, Request()));
        Assert.Single(results, result => result.Status == TeamInvitationStatus.Created);
        Assert.Single(results, result => result.Status == TeamInvitationStatus.Conflict);
        await using var check = fixture.CreateContext();
        Assert.Single(await check.WorkspaceInvitations.ToListAsync());
        Assert.Equal(7, await check.WorkspaceUsers.CountAsync());
    }

    [Fact]
    public async Task FailedCommit_PreservesPreviousLinkAndItsRole()
    {
        var original = (await Invitations().InviteAsync(1, 1, Request())).Invitation!;
        await using var setup = fixture.CreateContext();
        await setup.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION invitation_failure() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'invitation commit failure'; END $$
            """);
        await setup.Database.ExecuteSqlRawAsync("""
            CREATE CONSTRAINT TRIGGER invitation_failure AFTER UPDATE ON "WorkspaceInvitations"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION invitation_failure()
            """);
        try
        {
            await Assert.ThrowsAsync<PostgresException>(() => Invitations().InviteAsync(1, 1, Request(role: WorkspaceRole.WorkspaceAdmin)));
            Assert.Equal(WorkspaceRole.Normal, (await Preview().ReadAsync(Access(original)))!.Role);
        }
        finally
        {
            await setup.Database.ExecuteSqlRawAsync("DROP TRIGGER invitation_failure ON \"WorkspaceInvitations\"");
            await setup.Database.ExecuteSqlRawAsync("DROP FUNCTION invitation_failure()");
        }
    }

    [Fact]
    public async Task Endpoints_RequireAnAdministratorAndReturnOnlyTheNewPrivateLink()
    {
        await using var factory = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var admin = Client(factory, 1, "Normal");
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/users")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync("/api/users", Request())).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/invitations")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync("/api/users", Request("invalid"))).StatusCode);
        var response = await admin.PostAsJsonAsync("/api/users", Request());
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.True(response.Headers.CacheControl!.NoStore);
        var created = (await response.Content.ReadFromJsonAsync<CreatedInvitationResponse>(Json))!;
        var listResponse = await admin.GetAsync("/api/invitations");
        Assert.True(listResponse.Headers.CacheControl!.NoStore);
        var list = await listResponse.Content.ReadAsStringAsync();
        Assert.DoesNotContain(created.Token, list);
        Assert.DoesNotContain("tokenHash", list);
        Assert.Equal(3, (await admin.GetFromJsonAsync<List<WorkspaceUserResponse>>("/api/users", Json))!.Count);
        var preview = await anonymous.PostAsJsonAsync("/api/invitations/preview", Access(created));
        Assert.Equal(HttpStatusCode.OK, preview.StatusCode);
        Assert.True(preview.Headers.CacheControl!.NoStore);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync("/api/invitations/accept", Access(created))).StatusCode);
        using var member = Client(factory, 2, "WorkspaceAdmin");
        Assert.Equal(HttpStatusCode.Forbidden, (await member.PostAsJsonAsync("/api/users", Request())).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await member.GetAsync("/api/invitations")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await member.DeleteAsync($"/api/invitations/{created.Invitation.InvitationId}")).StatusCode);
        using var recipient = Client(factory, 3, "Normal");
        var joined = await recipient.PostAsJsonAsync("/api/invitations/accept", Access(created));
        Assert.Equal(HttpStatusCode.OK, joined.StatusCode);
        Assert.True(joined.Headers.Contains("Set-Cookie"));
        var current = (await joined.Content.ReadFromJsonAsync<CurrentUserResponse>(Json))!;
        Assert.Equal(1, current.WorkspaceId);
        Assert.Equal(WorkspaceRole.Normal, current.WorkspaceRole);
        Assert.Empty((await admin.GetFromJsonAsync<List<WorkspaceInvitationResponse>>("/api/invitations", Json))!);
        Assert.Equal(HttpStatusCode.NotFound, (await anonymous.PostAsJsonAsync("/api/invitations/preview", Access(created))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.DeleteAsync($"/api/invitations/{created.Invitation.InvitationId}")).StatusCode);
        var renewed = (await (await admin.PostAsJsonAsync("/api/users", Request())).Content.ReadFromJsonAsync<CreatedInvitationResponse>(Json))!;
        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/api/invitations/{renewed.Invitation.InvitationId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await recipient.PostAsJsonAsync("/api/invitations/accept", Access(renewed))).StatusCode);
    }

    private InvitationPreview Preview() => new(Factory(), new Clock());
    private static InvitationAccessRequest Access(CreatedInvitationResponse invitation) =>
        new() { InvitationId = invitation.Invitation.InvitationId, Token = invitation.Token };

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-an-email")]
    [InlineData("a@@example.test")]
    public async Task InvalidEmail_DoesNotWrite(string? email)
    {
        Assert.Equal(TeamInvitationStatus.Invalid, (await Invitations().InviteAsync(1, 1, Request(email!))).Status);
        await AssertNoInvitation();
    }

    [Fact]
    public async Task OversizedEmailAndUnknownRole_DoNotWrite()
    {
        Assert.Equal(TeamInvitationStatus.Invalid, (await Invitations().InviteAsync(1, 1, Request(new string('x', 320) + "@example.test"))).Status);
        Assert.Equal(TeamInvitationStatus.Invalid, (await Invitations().InviteAsync(1, 1, Request(role: (WorkspaceRole)99))).Status);
        await AssertNoInvitation();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task UnrelatedStorageFailures_AreNotMisreportedAsInvitationConflicts(int failure)
    {
        Exception exception = failure switch
        {
            0 => new InvalidOperationException("Storage unavailable"),
            1 => new PostgresException("Foreign key", "ERROR", "ERROR", PostgresErrorCodes.ForeignKeyViolation, constraintName: "FK_WorkspaceUsers"),
            _ => new PostgresException("Unrelated uniqueness", "ERROR", "ERROR", PostgresErrorCodes.UniqueViolation, constraintName: "IX_Users_IdentityProvider_ProviderSubjectId")
        };
        var interceptor = new BeforeMembershipSave(() => Task.FromException(exception));
        Assert.Same(exception, await Assert.ThrowsAsync(exception.GetType(), () => Invitations(interceptor).InviteAsync(1, 1, Request())));
        await AssertNoInvitation();
    }

    private static InviteUserRequest Request(string email = NewEmail, WorkspaceRole role = WorkspaceRole.Normal) => new() { Email = email, Role = role };
    private TeamInvitations Invitations(params IInterceptor[] interceptors) => new(Factory(interceptors), new Clock(), NullLogger<TeamInvitations>.Instance);
    private IDbContextFactory<AppDbContext> Factory(params IInterceptor[] interceptors) => new TestDbContextFactory(
        new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString).AddInterceptors(interceptors).Options);
    private async Task AssertNoInvitation()
    {
        await using var check = fixture.CreateContext();
        Assert.Equal(5, await check.Users.CountAsync());
        Assert.Equal(7, await check.WorkspaceUsers.CountAsync());
        Assert.False(await check.Users.AnyAsync(u => u.Email == NewEmail));
        Assert.Empty(await check.WorkspaceInvitations.ToListAsync());
    }
    private static HttpClient Client(MembershipWebApplicationFactory factory, int actor, string role)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, "1");
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, actor.ToString());
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceRoleHeader, role);
        return client;
    }
    private sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class CountReads : DbCommandInterceptor
    {
        public int Count { get; private set; }
        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData eventData,
            InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            Count++;
            return ValueTask.FromResult(result);
        }
    }
}
