using System.Net;
using System.Net.Http.Json;
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
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class WorkspaceDetailsTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var db = fixture.CreateContext();
        db.Workspaces.AddRange(Enumerable.Range(1, 4).Select(id => new Workspace
        {
            Id = id, Name = $"Workspace {id}", Slug = $"workspace-{id}", IsDeleted = id == 3, HasCompletedWelcome = true
        }));
        db.Users.AddRange(new User { Id = 1, Email = "owner@example.test", ActiveWorkspaceId = 1 },
            new User { Id = 2, Email = "deleted@example.test", IsDeleted = true });
        db.WorkspaceUsers.AddRange(Enumerable.Range(1, 3).Select(id => new WorkspaceUser
        {
            WorkspaceId = id, UserId = 1, WorkspaceRole = id == 2 ? WorkspaceRole.Normal : WorkspaceRole.WorkspaceAdmin
        }));
        db.WorkspaceUsers.Add(new WorkspaceUser { WorkspaceId = 1, UserId = 2, WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
        await db.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData(1, 4, WorkspaceDetailsStatus.NotFound)]
    [InlineData(1, 999, WorkspaceDetailsStatus.NotFound)]
    [InlineData(1, 3, WorkspaceDetailsStatus.NotFound)]
    [InlineData(2, 1, WorkspaceDetailsStatus.NotFound)]
    [InlineData(999, 1, WorkspaceDetailsStatus.NotFound)]
    [InlineData(1, 2, WorkspaceDetailsStatus.Forbidden)]
    public async Task Update_RequiresActiveAdministratorMembership(int user, int workspace, WorkspaceDetailsStatus expected)
    {
        Assert.Equal(expected, (await Details().UpdateAsync(user, workspace, new() { Name = "Edited" })).Status);
        await AssertOriginalWorkspace();
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("", null)]
    [InlineData("   ", null)]
    [InlineData("Library", "")]
    [InlineData("Library", "ab")]
    [InlineData("Library", "invalid--slug")]
    [InlineData("Library", "-invalid")]
    [InlineData("Library", "Invalid")]
    public async Task Update_ValidatesBeforeWriting(string? name, string? slug)
    {
        var result = await Details().UpdateAsync(1, 1, new() { Name = name!, Slug = slug });
        Assert.Equal(WorkspaceDetailsStatus.Invalid, result.Status);
        Assert.NotNull(result.Error);
        await AssertOriginalWorkspace();
    }

    [Fact]
    public async Task Update_ValidatesLengthsAtTheirBoundaries()
    {
        Assert.Equal(WorkspaceDetailsStatus.Invalid, (await Details().UpdateAsync(1, 1, new() { Name = new string('a', 201) })).Status);
        Assert.Equal(WorkspaceDetailsStatus.Invalid, (await Details().UpdateAsync(1, 1, new() { Name = "Library", Slug = new string('a', 51) })).Status);
        var result = await Details().UpdateAsync(1, 1, new() { Name = new string('a', 200), Slug = new string('a', 50) });
        Assert.Equal(WorkspaceDetailsStatus.Updated, result.Status);
        Assert.Equal(200, result.Workspace!.WorkspaceName.Length);
        Assert.Equal(50, result.Workspace.Slug!.Length);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("new-gallery")]
    [InlineData("workspace-1")]
    public async Task Update_ChangesOnlyRequestedMetadata(string? slug)
    {
        await using var before = fixture.CreateContext();
        var created = (await before.Workspaces.SingleAsync(w => w.Id == 1)).CreatedAt;
        var result = await Details().UpdateAsync(1, 1, new() { Name = "  New Library  ", Slug = slug });
        Assert.Equal(WorkspaceDetailsStatus.Updated, result.Status);
        var response = Assert.IsType<UpdateWorkspaceResponse>(result.Workspace);
        Assert.Equal(1, response.WorkspaceId);
        Assert.Equal("New Library", response.WorkspaceName);
        Assert.Equal(slug, response.Slug);
        Assert.Equal(slug is null ? null : $"/public/{slug}", response.PublicUrl);
        await using var check = fixture.CreateContext();
        var workspace = await check.Workspaces.SingleAsync(w => w.Id == 1);
        Assert.Equal(response.WorkspaceName, workspace.Name);
        Assert.Equal(slug, workspace.Slug);
        Assert.True(workspace.HasCompletedWelcome);
        Assert.False(workspace.IsDeleted);
        Assert.Equal(created, workspace.CreatedAt);
        Assert.Equal(1, (await check.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
        Assert.Equal(4, await check.WorkspaceUsers.CountAsync());
    }

    [Fact]
    public async Task UnchangedDetails_DoNotWrite()
    {
        var rejectWrite = new BeforeMembershipSave(() => throw new InvalidOperationException("Unexpected write"));
        Assert.Equal(WorkspaceDetailsStatus.Updated, (await Details(rejectWrite).UpdateAsync(1, 1, new() { Name = "Workspace 1", Slug = "workspace-1" })).Status);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Slugs_RemainReservedForActiveAndRecoverableWorkspaces(int owner)
    {
        var repository = new WorkspaceRepository(Factory());
        Assert.True(await repository.IsSlugTakenAsync($"workspace-{owner}"));
        Assert.True(await repository.IsSlugTakenAsync($"workspace-{owner}", 1));
        Assert.False(await repository.IsSlugTakenAsync($"workspace-{owner}", owner));
        Assert.False(await repository.IsSlugTakenAsync("available"));
        var result = await Details().UpdateAsync(1, 1, new() { Name = "Edited", Slug = $"workspace-{owner}" });
        Assert.Equal(WorkspaceDetailsStatus.Conflict, result.Status);
        Assert.Equal("This slug is already taken", result.Error);
        await AssertOriginalWorkspace();
    }

    [Fact]
    public async Task ConcurrentEdits_DoNotOverwriteEachOther()
    {
        var details = Details(new SynchronizedSaves());
        var results = await Task.WhenAll(details.UpdateAsync(1, 1, new() { Name = "First", Slug = "first" }),
            details.UpdateAsync(1, 1, new() { Name = "Second", Slug = "second" })).WaitAsync(TimeSpan.FromSeconds(20));
        var saved = Assert.Single(results, r => r.Status == WorkspaceDetailsStatus.Updated);
        Assert.Single(results, r => r.Status == WorkspaceDetailsStatus.Conflict);
        await using var check = fixture.CreateContext();
        var workspace = await check.Workspaces.SingleAsync(w => w.Id == 1);
        Assert.Equal(saved.Workspace!.WorkspaceName, workspace.Name);
        Assert.Equal(saved.Workspace.Slug, workspace.Slug);
    }

    [Fact]
    public async Task ConcurrentSlugClaims_ReportConflictWithoutPartialNameUpdates()
    {
        await using (var db = fixture.CreateContext())
            await db.WorkspaceUsers.Where(m => m.UserId == 1 && m.WorkspaceId == 2).ExecuteUpdateAsync(s => s.SetProperty(m => m.WorkspaceRole, WorkspaceRole.WorkspaceAdmin));
        var details = Details(new SynchronizedSaves());
        var results = await Task.WhenAll(details.UpdateAsync(1, 1, new() { Name = "First", Slug = "shared-url" }),
            details.UpdateAsync(1, 2, new() { Name = "Second", Slug = "shared-url" })).WaitAsync(TimeSpan.FromSeconds(20));
        var saved = Assert.Single(results, r => r.Status == WorkspaceDetailsStatus.Updated);
        Assert.Single(results, r => r.Status == WorkspaceDetailsStatus.Conflict);
        await using var check = fixture.CreateContext();
        Assert.Single(await check.Workspaces.Where(w => w.Slug == "shared-url").ToListAsync());
        var loser = saved.Workspace!.WorkspaceId == 1 ? 2 : 1;
        Assert.Equal($"Workspace {loser}", (await check.Workspaces.SingleAsync(w => w.Id == loser)).Name);
    }

    [Fact]
    public async Task WorkspaceDeletionDuringEdit_CannotBeOverwritten()
    {
        var delete = new BeforeMembershipSave(async () =>
        {
            await using var db = fixture.CreateContext();
            await db.Workspaces.Where(w => w.Id == 1).ExecuteUpdateAsync(s => s.SetProperty(w => w.IsDeleted, true));
        });
        Assert.Equal(WorkspaceDetailsStatus.Conflict, (await Details(delete).UpdateAsync(1, 1, new() { Name = "Edited" })).Status);
        await using var check = fixture.CreateContext();
        var workspace = await check.Workspaces.SingleAsync(w => w.Id == 1);
        Assert.True(workspace.IsDeleted);
        Assert.Equal("Workspace 1", workspace.Name);
    }

    [Theory]
    [InlineData("23505", "IX_Workspaces_Slug", true)]
    [InlineData("23505", "unrelated_constraint", false)]
    [InlineData("23503", "IX_Workspaces_Slug", false)]
    [InlineData("40001", null, true)]
    [InlineData(null, null, false)]
    public async Task StorageErrors_OnlyKnownConflictsBecomeReviewable(string? state, string? constraint, bool conflict)
    {
        Exception exception = state is null ? new InvalidOperationException("Storage unavailable") :
            new DbUpdateException("Write failed", new PostgresException("Storage error", "ERROR", "ERROR", state, constraintName: constraint));
        var details = Details(new BeforeMembershipSave(() => throw exception));
        if (conflict)
        {
            var result = await details.UpdateAsync(1, 1, new() { Name = "Edited" });
            Assert.Equal(WorkspaceDetailsStatus.Conflict, result.Status);
            Assert.Contains("Refresh", result.Error);
            Assert.Null(result.Workspace);
        }
        else Assert.Same(exception, await Assert.ThrowsAnyAsync<Exception>(() => details.UpdateAsync(1, 1, new() { Name = "Edited" })));
        await AssertOriginalWorkspace();
    }

    [Fact]
    public async Task CommitFailure_RollsBackSavedDetailsAndDoesNotLogSuccess()
    {
        await using var setup = fixture.CreateContext();
        await setup.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION workspace_details_failure() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'Workspace details test failure'; END $$
            """);
        await setup.Database.ExecuteSqlRawAsync("""
            CREATE CONSTRAINT TRIGGER workspace_details_failure AFTER UPDATE ON "Workspaces"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION workspace_details_failure()
            """);
        try
        {
            var log = new Mock<ILogger<WorkspaceDetails>>(MockBehavior.Strict);
            await Assert.ThrowsAsync<PostgresException>(() => new WorkspaceDetails(Factory(), log.Object).UpdateAsync(1, 1, new() { Name = "Edited" }));
            log.VerifyNoOtherCalls();
            await AssertOriginalWorkspace();
        }
        finally
        {
            await setup.Database.ExecuteSqlRawAsync("DROP TRIGGER workspace_details_failure ON \"Workspaces\"");
            await setup.Database.ExecuteSqlRawAsync("DROP FUNCTION workspace_details_failure()");
        }
    }

    [Fact]
    public async Task Endpoint_UsesCurrentMembershipAndAvailabilityMatchesTheWrite()
    {
        await using var factory = new MembershipWebApplicationFactory(fixture.ConnectionString);
        Assert.IsType<WorkspaceDetails>(factory.Services.GetRequiredService<IWorkspaceDetails>());
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, "1");
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, "1");
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceRoleHeader, "WorkspaceAdmin");
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PutAsJsonAsync("/api/workspaces/2", new UpdateWorkspaceRequest { Name = "Unauthorized" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PutAsJsonAsync("/api/workspaces/3", new UpdateWorkspaceRequest { Name = "Deleted" })).StatusCode);
        Assert.False((await client.GetFromJsonAsync<CheckSlugResponse>("/api/workspaces/check-slug/workspace-3"))!.IsAvailable);
        Assert.Equal(HttpStatusCode.Conflict, (await client.PutAsJsonAsync("/api/workspaces/1", new UpdateWorkspaceRequest { Name = "Edited", Slug = "workspace-3" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PutAsJsonAsync("/api/workspaces/1", new UpdateWorkspaceRequest { Name = " " })).StatusCode);
        client.DefaultRequestHeaders.Remove(TestAuthHandler.WorkspaceRoleHeader);
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceRoleHeader, "Normal");
        var response = await client.PutAsJsonAsync("/api/workspaces/1", new UpdateWorkspaceRequest { Name = "Edited", Slug = "library" });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(response.Headers.Contains("Set-Cookie"));
        Assert.Equal("/public/library", (await response.Content.ReadFromJsonAsync<UpdateWorkspaceResponse>())!.PublicUrl);
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PutAsJsonAsync("/api/workspaces/1", new UpdateWorkspaceRequest { Name = "Unauthorized" })).StatusCode);
    }

    private WorkspaceDetails Details(params IInterceptor[] interceptors) => new(Factory(interceptors), NullLogger<WorkspaceDetails>.Instance);
    private IDbContextFactory<AppDbContext> Factory(params IInterceptor[] interceptors) => new TestDbContextFactory(
        new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString).AddInterceptors(interceptors).Options);
    private async Task AssertOriginalWorkspace()
    {
        await using var check = fixture.CreateContext();
        var workspace = await check.Workspaces.SingleAsync(w => w.Id == 1);
        Assert.Equal("Workspace 1", workspace.Name);
        Assert.Equal("workspace-1", workspace.Slug);
    }
}
