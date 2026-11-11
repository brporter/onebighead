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
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public partial class WorkspaceWelcomeTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var db = fixture.CreateContext();
        db.Workspaces.AddRange(Enumerable.Range(1, 4).Select(id => new Workspace
        {
            Id = id, Name = $"Workspace {id}", Slug = $"workspace-{id}", IsDeleted = id == 3
        }));
        db.Users.AddRange(new User { Id = 1, Email = "current@example.test", ActiveWorkspaceId = 1 },
            new User { Id = 2, Email = "deleted@example.test", IsDeleted = true, ActiveWorkspaceId = 1 },
            new User { Id = 3, Email = "other-admin@example.test", ActiveWorkspaceId = 1 });
        db.WorkspaceUsers.AddRange(Enumerable.Range(1, 3).Select(id => new WorkspaceUser
        {
            WorkspaceId = id, UserId = 1, WorkspaceRole = id == 2 ? WorkspaceRole.Normal : WorkspaceRole.WorkspaceAdmin
        }));
        db.WorkspaceUsers.AddRange(new WorkspaceUser { WorkspaceId = 1, UserId = 2, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
            new WorkspaceUser { WorkspaceId = 1, UserId = 3, WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
        await db.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData(1, 4, WorkspaceWelcomeStatus.NotFound)]
    [InlineData(1, 999, WorkspaceWelcomeStatus.NotFound)]
    [InlineData(1, 3, WorkspaceWelcomeStatus.NotFound)]
    [InlineData(2, 1, WorkspaceWelcomeStatus.NotFound)]
    [InlineData(999, 1, WorkspaceWelcomeStatus.NotFound)]
    [InlineData(1, 2, WorkspaceWelcomeStatus.Forbidden)]
    public async Task Complete_RequiresCurrentActiveAdministrator(int user, int workspace, WorkspaceWelcomeStatus expected)
    {
        Assert.Equal(expected, (await Welcome().CompleteAsync(user, workspace, new() { WorkspaceName = "Edited" })).Status);
        await AssertOriginalWorkspace();
    }

    [Theory]
    [InlineData(null)]
    [InlineData(2)]
    public async Task ChangedActiveWorkspace_RequiresSessionRefresh(int? active)
    {
        await using var db = fixture.CreateContext();
        await db.Users.Where(u => u.Id == 1).ExecuteUpdateAsync(s => s.SetProperty(u => u.ActiveWorkspaceId, active));
        var result = await Welcome().CompleteAsync(1, 1, new());
        Assert.Equal(WorkspaceWelcomeStatus.Conflict, result.Status);
        Assert.Contains("active workspace changed", result.Error);
        await AssertOriginalWorkspace();
    }

    [Theory]
    [InlineData("  Library  ", "Library")]
    [InlineData(null, "current@example.test")]
    [InlineData("", "current@example.test")]
    [InlineData("  ", "current@example.test")]
    public async Task Complete_UsesProvidedNameOrCurrentAccountEmailAndPreservesOtherFields(string? name, string expected)
    {
        await using var before = fixture.CreateContext();
        var original = await before.Workspaces.SingleAsync(w => w.Id == 1);
        var result = await Welcome().CompleteAsync(1, 1, new() { WorkspaceName = name });
        Assert.Equal(WorkspaceWelcomeStatus.Completed, result.Status);
        var response = Assert.IsType<CompleteWelcomeResponse>(result.Workspace);
        Assert.Equal(1, response.WorkspaceId);
        Assert.Equal(expected, response.WorkspaceName);
        Assert.True(response.HasCompletedWelcome);
        await using var check = fixture.CreateContext();
        var saved = await check.Workspaces.SingleAsync(w => w.Id == 1);
        Assert.Equal(expected, saved.Name);
        Assert.True(saved.HasCompletedWelcome);
        Assert.Equal(original.Slug, saved.Slug);
        Assert.Equal(original.CreatedAt, saved.CreatedAt);
        Assert.False(saved.IsDeleted);
        Assert.Equal(1, (await check.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
        Assert.Equal(5, await check.WorkspaceUsers.CountAsync());
    }

    [Fact]
    public async Task MissingAccountEmail_PreservesTheExistingWorkspaceName()
    {
        await using var db = fixture.CreateContext();
        await db.Users.Where(u => u.Id == 1).ExecuteUpdateAsync(s => s.SetProperty(u => u.Email, ""));
        var result = await Welcome().CompleteAsync(1, 1, new());
        Assert.Equal(WorkspaceWelcomeStatus.Completed, result.Status);
        Assert.Equal("Workspace 1", result.Workspace!.WorkspaceName);
    }

    [Fact]
    public async Task LongNames_AreRejectedBeforeWritingIncludingEmailFallback()
    {
        var longName = new string('a', 201);
        Assert.Equal(WorkspaceWelcomeStatus.Invalid, (await Welcome().CompleteAsync(1, 1, new() { WorkspaceName = longName })).Status);
        await using var db = fixture.CreateContext();
        await db.Users.Where(u => u.Id == 1).ExecuteUpdateAsync(s => s.SetProperty(u => u.Email, longName));
        var fallback = await Welcome().CompleteAsync(1, 1, new());
        Assert.Equal(WorkspaceWelcomeStatus.Invalid, fallback.Status);
        Assert.Contains("200", fallback.Error);
        await AssertOriginalWorkspace();
        var boundary = await Welcome().CompleteAsync(1, 1, new() { WorkspaceName = new string('a', 200) });
        Assert.Equal(WorkspaceWelcomeStatus.Completed, boundary.Status);
        Assert.Equal(200, boundary.Workspace!.WorkspaceName.Length);
    }

    [Fact]
    public async Task RepeatCompletion_IsReadOnlyAndPreservesLaterSettingsChanges()
    {
        Assert.Equal(WorkspaceWelcomeStatus.Completed, (await Welcome().CompleteAsync(1, 1, new() { WorkspaceName = "First" })).Status);
        var details = new WorkspaceDetails(Factory(), NullLogger<WorkspaceDetails>.Instance);
        Assert.Equal(WorkspaceDetailsStatus.Updated, (await details.UpdateAsync(1, 1, new() { Name = "Edited in settings", Slug = "new-url" })).Status);
        var rejectWrite = new BeforeMembershipSave(() => throw new InvalidOperationException("Repeated welcome must not write"));
        var repeated = await Welcome(rejectWrite).CompleteAsync(1, 1, new() { WorkspaceName = "Stale welcome name" });
        Assert.Equal(WorkspaceWelcomeStatus.Completed, repeated.Status);
        Assert.Equal("Edited in settings", repeated.Workspace!.WorkspaceName);
        await using var db = fixture.CreateContext();
        Assert.Equal("new-url", (await db.Workspaces.SingleAsync(w => w.Id == 1)).Slug);
    }

    [Fact]
    public async Task ConcurrentCompletions_CommitOneNameAndAllowReadOnlyRecovery()
    {
        var welcome = Welcome(new SynchronizedSaves());
        var results = await Task.WhenAll(welcome.CompleteAsync(1, 1, new() { WorkspaceName = "First" }),
            welcome.CompleteAsync(3, 1, new() { WorkspaceName = "Second" })).WaitAsync(TimeSpan.FromSeconds(20));
        var completed = Assert.Single(results, r => r.Status == WorkspaceWelcomeStatus.Completed);
        var conflict = Assert.Single(results, r => r.Status == WorkspaceWelcomeStatus.Conflict);
        Assert.Null(conflict.Workspace);
        var recovered = await Welcome().CompleteAsync(1, 1, new() { WorkspaceName = "Retry cannot overwrite" });
        Assert.Equal(completed.Workspace!.WorkspaceName, recovered.Workspace!.WorkspaceName);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task MembershipRevocationDuringCompletion_CannotCommitStaleAuthorization(bool remove, bool createCollection)
    {
        if (createCollection) await SeedWelcomeTheme();
        var revoke = new BeforeMembershipSave(async () =>
        {
            var team = new TeamMembershipChanges(Factory(), TimeProvider.System, NullLogger<TeamMembershipChanges>.Instance);
            var result = remove ? await team.RemoveAsync(3, 1, 1) : await team.ChangeRoleAsync(3, 1, 1, WorkspaceRole.Normal);
            Assert.Equal(TeamMembershipStatus.Changed, result.Status);
        });
        Assert.Equal(WorkspaceWelcomeStatus.Conflict, (await Welcome(revoke).CompleteAsync(1, 1, createCollection ? CollectionWelcome() : new() { WorkspaceName = "Stale" })).Status);
        await AssertOriginalWorkspace();
        await AssertNoWelcomeCollection();
        Assert.Equal(remove ? WorkspaceWelcomeStatus.NotFound : WorkspaceWelcomeStatus.Forbidden,
            (await Welcome().CompleteAsync(1, 1, new())).Status);
    }

    [Fact]
    public async Task DeletionDuringCompletion_CannotRestoreOrRenameTheWorkspace()
    {
        var delete = new BeforeMembershipSave(async () =>
        {
            await using var db = fixture.CreateContext();
            await db.Workspaces.Where(w => w.Id == 1).ExecuteUpdateAsync(s => s.SetProperty(w => w.IsDeleted, true));
        });
        Assert.Equal(WorkspaceWelcomeStatus.Conflict, (await Welcome(delete).CompleteAsync(1, 1, new() { WorkspaceName = "Stale" })).Status);
        await AssertOriginalWorkspace();
        await using var check = fixture.CreateContext();
        Assert.True((await check.Workspaces.SingleAsync(w => w.Id == 1)).IsDeleted);
    }

    [Fact]
    public async Task StorageFailure_PropagatesAndDoesNotCommitCompletion()
    {
        var failure = new InvalidOperationException("Storage unavailable");
        Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Welcome(new BeforeMembershipSave(() => throw failure)).CompleteAsync(1, 1, new())));
        await AssertOriginalWorkspace();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CommitFailure_RollsBackNameAndCompletionWithoutLoggingSuccess(bool includeCollection)
    {
        if (includeCollection) await SeedWelcomeTheme();
        await using var setup = fixture.CreateContext();
        await setup.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION workspace_welcome_failure() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'Welcome test failure'; END $$
            """);
        await setup.Database.ExecuteSqlRawAsync("""
            CREATE CONSTRAINT TRIGGER workspace_welcome_failure AFTER UPDATE ON "Workspaces"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION workspace_welcome_failure()
            """);
        try
        {
            var log = new Mock<ILogger<WorkspaceWelcome>>(MockBehavior.Strict);
            await Assert.ThrowsAsync<PostgresException>(() => new WorkspaceWelcome(Factory(), new WorkspaceStatisticsWriter(), TimeProvider.System, log.Object).CompleteAsync(1, 1, includeCollection ? CollectionWelcome() : new() { WorkspaceName = "Unsaved" }));
            log.VerifyNoOtherCalls();
            await AssertOriginalWorkspace();
            await AssertNoWelcomeCollection();
        }
        finally
        {
            await setup.Database.ExecuteSqlRawAsync("DROP TRIGGER workspace_welcome_failure ON \"Workspaces\"");
            await setup.Database.ExecuteSqlRawAsync("DROP FUNCTION workspace_welcome_failure()");
        }
    }

    [Fact]
    public async Task Endpoint_UsesCurrentMembershipAndEmailInsteadOfStaleClaims()
    {
        await using var factory = new MembershipWebApplicationFactory(fixture.ConnectionString);
        Assert.IsType<WorkspaceWelcome>(factory.Services.GetRequiredService<IWorkspaceWelcome>());
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, "1");
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, "2");
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceRoleHeader, "WorkspaceAdmin");
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync("/api/auth/complete-welcome", new CompleteWelcomeRequest())).StatusCode);
        client.DefaultRequestHeaders.Remove(TestAuthHandler.WorkspaceIdHeader);
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, "1");
        client.DefaultRequestHeaders.Remove(TestAuthHandler.WorkspaceRoleHeader);
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceRoleHeader, "Normal");
        client.DefaultRequestHeaders.Add(TestAuthHandler.EmailHeader, "stale@example.test");
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/auth/complete-welcome", new CompleteWelcomeRequest { WorkspaceName = new string('a', 201) })).StatusCode);
        var response = await client.PostAsJsonAsync("/api/auth/complete-welcome", new CompleteWelcomeRequest());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var workspace = (await response.Content.ReadFromJsonAsync<CompleteWelcomeResponse>())!;
        Assert.Equal("current@example.test", workspace.WorkspaceName);
        Assert.Equal(1, workspace.WorkspaceId);
        Assert.True(workspace.HasCompletedWelcome);
        Assert.False(response.Headers.Contains("Set-Cookie"));
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync("/api/auth/complete-welcome", new CompleteWelcomeRequest())).StatusCode);
    }

    private WorkspaceWelcome Welcome(params IInterceptor[] interceptors) => new(Factory(interceptors), new WorkspaceStatisticsWriter(), TimeProvider.System, NullLogger<WorkspaceWelcome>.Instance);
    private IDbContextFactory<AppDbContext> Factory(params IInterceptor[] interceptors) => new TestDbContextFactory(
        new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString).AddInterceptors(interceptors).Options);
    private async Task AssertOriginalWorkspace()
    {
        await using var db = fixture.CreateContext();
        var workspace = await db.Workspaces.SingleAsync(w => w.Id == 1);
        Assert.Equal("Workspace 1", workspace.Name);
        Assert.Equal("workspace-1", workspace.Slug);
        Assert.False(workspace.HasCompletedWelcome);
    }
}
