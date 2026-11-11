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
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public partial class WorkspaceSetupTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 12, 0, 0, TimeSpan.Zero);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var db = fixture.CreateContext();
        db.Workspaces.AddRange(new Workspace { Id = 1, Name = "Existing" }, new Workspace { Id = 4, Name = "Deleted", IsDeleted = true });
        db.Users.AddRange(new User { Id = 1, Email = "member@example.test", ActiveWorkspaceId = 1 },
            new User { Id = 2, Email = "deleted@example.test", IsDeleted = true }, new User { Id = 3, Email = "new@example.test" });
        db.WorkspaceUsers.AddRange(new WorkspaceUser { UserId = 1, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.Normal },
            new WorkspaceUser { UserId = 1, WorkspaceId = 4, WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
        db.ItemTemplates.AddRange(new ItemTemplate { Id = 1, Name = "System", TemplateKey = Guid.NewGuid() },
            new ItemTemplate { Id = 2, Name = "Private", WorkspaceId = 1, TemplateKey = Guid.NewGuid() });
        db.CollectionThemes.AddRange(new CollectionTheme
        {
            Id = 10, Name = "General", SortOrder = 100, ThemeTemplates = [new() { ItemTemplateId = 1 }],
            ThemeCategories = [new() { Name = "Child", ParentName = " Root ", SortOrder = 3, Description = "Child details" }, new() { Name = "Root", SortOrder = 7 }]
        }, new CollectionTheme { Id = 20, Name = "Books", SortOrder = 0, ThemeCategories = [new() { Name = "Authors" }] },
            new CollectionTheme { Id = 21, Name = "Art", SortOrder = 0, ThemeCategories = [new() { Name = "Artists" }] });
        await db.SaveChangesAsync();
        await db.Database.ExecuteSqlRawAsync("ALTER SEQUENCE \"Workspaces_Id_seq\" RESTART WITH 5");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData(2)]
    [InlineData(999)]
    public async Task Setup_RejectsMissingOrDeletedAccounts(int user)
    {
        Assert.Equal(WorkspaceSetupStatus.Forbidden, (await Setup().CreateAsync(user, Request())).Status);
        await AssertNothingCreated();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Setup_RequiresANonblankWorkspaceName(string? name)
    {
        Assert.Equal(WorkspaceSetupStatus.Invalid, (await Setup().CreateAsync(1, new() { RequestId = Guid.NewGuid(), WorkspaceName = name! })).Status);
        await AssertNothingCreated();
    }

    [Fact]
    public async Task Setup_EnforcesTheActualStorageLimits()
    {
        foreach (var request in new[] { new SetupWorkspaceRequest { RequestId = Guid.NewGuid(), WorkspaceName = new string('a', 201) },
            new() { RequestId = Guid.NewGuid(), WorkspaceName = "New", CollectionName = new string('b', 201) },
            new() { RequestId = Guid.NewGuid(), WorkspaceName = "New", CollectionDescription = new string('c', 1001) } })
        {
            var rejected = await Setup().CreateAsync(1, request);
            Assert.Equal(WorkspaceSetupStatus.Invalid, rejected.Status);
            Assert.NotNull(rejected.Error);
        }
        await AssertNothingCreated();
        var boundary = await Setup().CreateAsync(1, new() { RequestId = Guid.NewGuid(), WorkspaceName = new string('a', 200), CollectionName = new string('b', 200), CollectionDescription = new string('c', 1000) });
        Assert.Equal(WorkspaceSetupStatus.Created, boundary.Status);
        await using var db = fixture.CreateContext();
        Assert.Equal(1000, (await db.Collections.SingleAsync()).Description.Length);
    }

    [Theory]
    [InlineData(1, null, "My Collection", "")]
    [InlineData(3, "   ", "My Collection", "")]
    [InlineData(1, "  First editions  ", "First editions", "  Signed copies  ")]
    public async Task Setup_CommitsGraphMembershipAndActivationAndReturnsTheSameSession(int userId, string? collectionName, string expectedName, string description)
    {
        var result = await Setup().CreateAsync(userId, new() { RequestId = Guid.NewGuid(), WorkspaceName = "  Study  ", CollectionName = collectionName, CollectionDescription = description });
        Assert.Equal(WorkspaceSetupStatus.Created, result.Status);
        var response = Assert.IsType<SetupWorkspaceResponse>(result.Workspace);
        var session = Assert.IsType<CurrentUserSession>(result.Session);
        Assert.Equal("Study", response.WorkspaceName);
        Assert.Equal(expectedName, response.CollectionName);
        Assert.Equal(response.WorkspaceId, session.User.ActiveWorkspaceId);
        Assert.Equal(response.WorkspaceId, session.Response.WorkspaceId);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, session.Response.WorkspaceRole);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, response.WorkspaceRole);
        Assert.True(session.Response.HasCompletedWelcome);
        Assert.DoesNotContain(session.Response.Workspaces, m => m.WorkspaceId == 4);
        Assert.Equal(userId == 1 ? 2 : 1, session.Response.Workspaces.Count);
        if (userId == 1) Assert.Equal(WorkspaceRole.Normal, session.Response.Workspaces.Single(m => m.WorkspaceId == 1).WorkspaceRole);

        await using var db = fixture.CreateContext();
        var workspace = await db.Workspaces.SingleAsync(w => w.Id == response.WorkspaceId);
        var collection = await db.Collections.SingleAsync();
        var membership = await db.WorkspaceUsers.SingleAsync(m => m.WorkspaceId == workspace.Id);
        Assert.Equal(Now.UtcDateTime, workspace.CreatedAt);
        Assert.Equal(Now.UtcDateTime, collection.CreatedAt);
        Assert.Equal(Now.UtcDateTime, membership.CreatedAt);
        Assert.True(workspace.HasCompletedWelcome);
        Assert.Equal(Visibility.Private, collection.Visibility);
        Assert.Equal(description.Trim(), collection.Description);
        Assert.Equal(expectedName, collection.Name);
        Assert.Equal(response.CollectionId, collection.Id);
        Assert.Equal(workspace.Id, collection.WorkspaceId);
        Assert.Equal(userId, membership.UserId);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, membership.WorkspaceRole);
        Assert.Equal(workspace.Id, (await db.Users.SingleAsync(u => u.Id == userId)).ActiveWorkspaceId);
        var categories = await db.Categories.ToListAsync();
        Assert.Equal(3, categories.Count);
        Assert.Single(categories, c => c.IsSystem);
        var root = categories.Single(c => c.Name == "Root");
        var child = categories.Single(c => c.Name == "Child");
        Assert.Equal(root.Id, child.ParentCategoryId);
        Assert.Equal(7, root.SortOrder);
        Assert.Equal(3, child.SortOrder);
        Assert.Equal("Child details", child.Description);
        Assert.All(categories, category => { Assert.Equal(workspace.Id, category.WorkspaceId); Assert.Equal(collection.Id, category.CollectionId); });
        Assert.Equal(1, (await db.CollectionItemTemplates.SingleAsync()).ItemTemplateId);
        var count = await db.WorkspaceStatistics.SingleAsync();
        Assert.Equal(workspace.Id, count.WorkspaceId);
        Assert.Equal(1, count.Value);
    }

    [Theory]
    [InlineData(20, "Authors")]
    [InlineData(999, "Root")]
    [InlineData(null, "Root")]
    public async Task ThemeSelection_UsesTheRequestedThemeOrGeneralFallback(int? themeId, string category)
    {
        var result = await Setup().CreateAsync(1, new() { RequestId = Guid.NewGuid(), WorkspaceName = "Library", ThemeId = themeId });
        Assert.Equal(WorkspaceSetupStatus.Created, result.Status);
        await using var db = fixture.CreateContext();
        Assert.True(await db.Categories.AnyAsync(c => c.Name == category));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MissingGeneral_UsesDeterministicFirstThemeOrAnEmptyCollection(bool noThemes)
    {
        await using var db = fixture.CreateContext();
        await db.CollectionThemes.Where(t => noThemes || t.Id == 10).ExecuteDeleteAsync();
        Assert.Equal(WorkspaceSetupStatus.Created, (await Setup().CreateAsync(1, Request())).Status);
        Assert.Equal(noThemes ? 1 : 2, await db.Categories.CountAsync());
        Assert.Equal(!noThemes, await db.Categories.AnyAsync(c => c.Name == "Authors"));
    }

    [Theory]
    [InlineData("case")]
    [InlineData("cycle")]
    [InlineData("duplicate")]
    [InlineData("foreign-template")]
    public async Task InvalidThemes_ReturnBadRequestWithoutGraphSessionOrCookieChanges(string kind)
    {
        await using var db = fixture.CreateContext();
        db.CollectionThemes.Add(new CollectionTheme
        {
            Id = 30, Name = "Invalid",
            ThemeTemplates = kind == "foreign-template" ? [new() { ItemTemplateId = 2 }] : [],
            ThemeCategories = kind == "foreign-template" ? [] : [new() { Name = "Root" },
                new() { Name = kind == "duplicate" ? " Root " : "Child", ParentName = kind == "case" ? "root" : "Child" }]
        });
        await db.SaveChangesAsync();
        await using var factory = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var client = Client(factory, 1);
        var response = await client.PostAsJsonAsync("/api/workspaces/setup", new SetupWorkspaceRequest { RequestId = Guid.NewGuid(), WorkspaceName = "New", ThemeId = 30 });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains(kind == "foreign-template" ? "unavailable" : "The selected theme", await response.Content.ReadAsStringAsync());
        Assert.False(response.Headers.Contains("Set-Cookie"));
        await AssertNothingCreated();
    }

    [Fact]
    public async Task ConcurrentSetups_CommitOneCompleteGraphAndReturnAConflictForTheOther()
    {
        var setup = Setup(new SynchronizedSaves());
        var results = await Task.WhenAll(setup.CreateAsync(1, Request()), setup.CreateAsync(1, Request())).WaitAsync(TimeSpan.FromSeconds(20));
        var saved = Assert.Single(results, r => r.Status == WorkspaceSetupStatus.Created);
        var conflict = Assert.Single(results, r => r.Status == WorkspaceSetupStatus.Conflict);
        Assert.Null(conflict.Workspace);
        Assert.Null(conflict.Session);
        Assert.Contains("Refresh", conflict.Error);
        await using var db = fixture.CreateContext();
        Assert.Equal(3, await db.Workspaces.CountAsync());
        Assert.Single(await db.Collections.ToListAsync());
        Assert.Equal(saved.Workspace!.WorkspaceId, (await db.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
        Assert.Single(await db.WorkspaceStatistics.ToListAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AccountChangesDuringSetup_DoNotCreateOrphansOrOverwriteTheAccount(bool deleted)
    {
        var change = new BeforeMembershipSave(async () =>
        {
            await using var db = fixture.CreateContext();
            if (deleted) await db.Users.Where(u => u.Id == 1).ExecuteUpdateAsync(s => s.SetProperty(u => u.IsDeleted, true));
            else await db.Users.Where(u => u.Id == 1).ExecuteUpdateAsync(s => s.SetProperty(u => u.ActiveWorkspaceId, 4));
        });
        Assert.Equal(WorkspaceSetupStatus.Conflict, (await Setup(change).CreateAsync(1, Request())).Status);
        await AssertNothingCreated(deleted ? 1 : 4);
        await using var check = fixture.CreateContext();
        Assert.Equal(deleted, (await check.Users.SingleAsync(u => u.Id == 1)).IsDeleted);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailureAfterSaving_RollsBackTheWholeGraphCountAndSession(bool duringCommit)
    {
        await using var db = fixture.CreateContext();
        if (duringCommit)
        {
            await db.Database.ExecuteSqlRawAsync("CREATE FUNCTION setup_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Setup test failure'; END $$");
            await db.Database.ExecuteSqlRawAsync("CREATE CONSTRAINT TRIGGER setup_failure AFTER INSERT ON \"Workspaces\" DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION setup_failure()");
        }
        else await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"WorkspaceStatistics\" ADD CONSTRAINT \"SetupCountFailure\" CHECK (\"Value\" < 1)");
        try
        {
            var observer = new ObserveSavedGraph();
            var log = new Mock<ILogger<WorkspaceSetup>>(MockBehavior.Strict);
            await Assert.ThrowsAsync<PostgresException>(() => new WorkspaceSetup(Factory(), observer, new Clock(), log.Object).CreateAsync(1, Request()));
            Assert.True(observer.SawSavedGraph);
            log.VerifyNoOtherCalls();
            await AssertNothingCreated();
        }
        finally
        {
            if (duringCommit)
            {
                await db.Database.ExecuteSqlRawAsync("DROP TRIGGER setup_failure ON \"Workspaces\"");
                await db.Database.ExecuteSqlRawAsync("DROP FUNCTION setup_failure()");
            }
            else await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"WorkspaceStatistics\" DROP CONSTRAINT \"SetupCountFailure\"");
        }
    }

    [Fact]
    public async Task ReferencedTemplateRemovedDuringSetup_RequiresReviewWithoutSavingAPartialWorkspace()
    {
        var remove = new BeforeMembershipSave(async () =>
        {
            await using var db = fixture.CreateContext();
            await db.ItemTemplates.Where(t => t.Id == 1).ExecuteDeleteAsync();
        });
        Assert.Equal(WorkspaceSetupStatus.Conflict, (await Setup(remove).CreateAsync(1, Request())).Status);
        await AssertNothingCreated();
    }

    [Fact]
    public async Task UnrelatedStorageFailure_PropagatesWithoutCommitting()
    {
        var error = new InvalidOperationException("Database unavailable");
        Assert.Same(error, await Assert.ThrowsAsync<InvalidOperationException>(() => Setup(new BeforeMembershipSave(() => throw error)).CreateAsync(1, Request())));
        await AssertNothingCreated();
    }

    [Fact]
    public async Task Endpoint_CreatesFromNoWorkspaceAndReturnsTheCommittedCookieAndThemePreview()
    {
        await using var factory = new MembershipWebApplicationFactory(fixture.ConnectionString);
        Assert.IsType<WorkspaceSetup>(factory.Services.GetRequiredService<IWorkspaceSetup>());
        using var client = Client(factory, 3);
        var preview = (await client.GetFromJsonAsync<CollectionThemeDto>("/api/themes/10"))!;
        var response = await client.PostAsJsonAsync("/api/workspaces/setup", new SetupWorkspaceRequest { RequestId = Guid.NewGuid(), WorkspaceName = "First", ThemeId = 10 });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = (await response.Content.ReadFromJsonAsync<SetupWorkspaceResponse>(JsonOptions))!;
        var cookie = Assert.Single(response.Headers.GetValues("Set-Cookie"));
        var principal = factory.Services.GetRequiredService<ITokenService>().ValidateAppToken(cookie.Split(';')[0].Split('=', 2)[1]);
        Assert.Equal(result.WorkspaceId.ToString(), principal!.FindFirst(ClaimNames.WorkspaceId)!.Value);
        Assert.Equal("WorkspaceAdmin", principal.FindFirst(ClaimNames.WorkspaceRole)!.Value);
        Assert.Equal("new@example.test", principal.FindFirst(System.Security.Claims.ClaimTypes.Email)!.Value);
        client.DefaultRequestHeaders.Remove(TestAuthHandler.WorkspaceIdHeader);
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, result.WorkspaceId.ToString());
        var categories = (await client.GetFromJsonAsync<List<CategoryResponse>>($"/api/categories?collectionId={result.CollectionId}", JsonOptions))!;
        Assert.Equal(preview.Categories.Select(c => c.Name), categories.Where(c => !c.IsSystem).Select(c => c.Name));
        Assert.Equal(preview.Categories.Select(c => c.SortOrder), categories.Where(c => !c.IsSystem).Select(c => c.SortOrder));
        Assert.All(categories, c => Assert.False(c.EffectiveIsPublic));
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync("/api/workspaces/setup", Request())).StatusCode);
        using var deleted = Client(factory, 2);
        Assert.Equal(HttpStatusCode.Forbidden, (await deleted.PostAsJsonAsync("/api/workspaces/setup", Request())).StatusCode);
        var invalid = await client.PostAsJsonAsync("/api/workspaces/setup", new SetupWorkspaceRequest { RequestId = Guid.NewGuid(), WorkspaceName = "New", CollectionDescription = new string('a', 1001) });
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        Assert.False(invalid.Headers.Contains("Set-Cookie"));
    }

    private static HttpClient Client(MembershipWebApplicationFactory factory, int user)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, user.ToString());
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, "0");
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceRoleHeader, "Normal");
        client.DefaultRequestHeaders.Add(TestAuthHandler.EmailHeader, "stale@example.test");
        return client;
    }
    private static SetupWorkspaceRequest Request() => new() { RequestId = Guid.NewGuid(), WorkspaceName = "New" };
    private WorkspaceSetup Setup(params IInterceptor[] interceptors) => new(Factory(interceptors), new WorkspaceStatisticsWriter(), new Clock(), NullLogger<WorkspaceSetup>.Instance);
    private IDbContextFactory<AppDbContext> Factory(params IInterceptor[] interceptors) => new TestDbContextFactory(
        new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString).AddInterceptors(interceptors).Options);
    private async Task AssertNothingCreated(int active = 1)
    {
        await using var db = fixture.CreateContext();
        Assert.Equal(2, await db.Workspaces.CountAsync());
        Assert.Equal(2, await db.WorkspaceUsers.CountAsync());
        Assert.Empty(await db.Collections.ToListAsync());
        Assert.Empty(await db.Categories.ToListAsync());
        Assert.Empty(await db.CollectionItemTemplates.ToListAsync());
        Assert.Empty(await db.WorkspaceStatistics.ToListAsync());
        Assert.Empty(await db.WorkspaceSetupReceipts.ToListAsync());
        Assert.Equal(active, (await db.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
    }
    private sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class ObserveSavedGraph : IWorkspaceStatisticsWriter
    {
        public bool SawSavedGraph { get; private set; }
        public async Task IncrementAsync(AppDbContext context, int workspaceId, StatisticType type, long amount = 1, DateOnly? date = null)
        {
            Assert.NotNull(context.Database.CurrentTransaction);
            Assert.Equal(1, await context.Collections.CountAsync());
            Assert.Equal(3, await context.Categories.CountAsync());
            Assert.Equal(1, await context.CollectionItemTemplates.CountAsync());
            Assert.Equal(workspaceId, (await context.Users.AsNoTracking().SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
            Assert.Equal(WorkspaceRole.WorkspaceAdmin, (await context.WorkspaceUsers.AsNoTracking().SingleAsync(m => m.WorkspaceId == workspaceId)).WorkspaceRole);
            SawSavedGraph = true;
            await new WorkspaceStatisticsWriter().IncrementAsync(context, workspaceId, type, amount, date);
        }
    }
}
