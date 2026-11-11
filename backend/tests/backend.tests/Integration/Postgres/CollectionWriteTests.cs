using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public partial class CollectionWriteTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var db = fixture.CreateContext();
        db.Workspaces.Add(new Workspace { Id = 1, Name = "Workspace" });
        db.Users.Add(new User { Id = 1, Email = "owner@example.test", ActiveWorkspaceId = 1 });
        db.WorkspaceUsers.Add(new WorkspaceUser { UserId = 1, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
        db.Collections.AddRange(new Collection { Id = 1, WorkspaceId = 1, Name = "First", Slug = "first", Visibility = Visibility.Public },
            new Collection { Id = 2, WorkspaceId = 1, Name = "Second", Slug = "second" });
        db.WorkspaceStatistics.AddRange(new WorkspaceStatistic { WorkspaceId = 1, StatisticType = StatisticType.CollectionCount, Date = DateOnly.MinValue, Value = 2 },
            new WorkspaceStatistic { WorkspaceId = 1, StatisticType = StatisticType.ItemCount, Date = DateOnly.MinValue, Value = 0 });
        await db.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Rename_DoesNotUndoAConcurrentPublicationChange()
    {
        var reads = 0;
        var change = new BeforeRead(async command =>
        {
            if (command.Contains("FROM \"Collections\"") && ++reads == 2)
            {
                await using var db = fixture.CreateContext();
                await db.Collections.Where(c => c.Id == 1).ExecuteUpdateAsync(set => set.SetProperty(c => c.Visibility, Visibility.Private));
            }
        });
        await using var app = new MembershipWebApplicationFactory(fixture.ConnectionString);
        await using var observed = app.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.AddDbContextFactory<AppDbContext>(options => options.UseNpgsql(fixture.ConnectionString).AddInterceptors(change))));
        using var client = Authenticate(observed.CreateClient());
        using var response = await client.PutAsJsonAsync("/api/collections/1", new UpdateCollectionRequest { Name = "Renamed" });
        await using var check = fixture.CreateContext();
        Assert.True(reads >= 2);
        Assert.Equal(Visibility.Private, (await check.Collections.SingleAsync(c => c.Id == 1)).Visibility);
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task Rename_WithAValidLongName_ProducesABoundedSlug()
    {
        await using var app = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var client = Authenticate(app.CreateClient());
        var name = new string('a', 150);
        using var response = await client.PutAsJsonAsync("/api/collections/1", new UpdateCollectionRequest { Name = name });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<Collection>();
        Assert.Equal(name, result!.Name);
        Assert.InRange(result.Slug.Length, 1, 100);
    }

    [Fact]
    public async Task Delete_RemovesNestedContentAndHighlightsAndCommitsStatisticsTogether()
    {
        await AddGraph();
        await using var app = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var client = Authenticate(app.CreateClient());
        using var response = await client.DeleteAsync("/api/collections/1");
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        await using var check = fixture.CreateContext();
        Assert.Equal(2, (await check.Collections.SingleAsync()).Id);
        Assert.Empty(await check.Items.ToListAsync());
        Assert.Empty(await check.Categories.ToListAsync());
        Assert.Empty(await check.CollectionItemHighlights.ToListAsync());
        Assert.Empty(await check.CollectionStatistics.ToListAsync());
        Assert.Equal(1, (await check.WorkspaceStatistics.SingleAsync(s => s.StatisticType == StatisticType.CollectionCount)).Value);
        Assert.Equal(0, (await check.WorkspaceStatistics.SingleAsync(s => s.StatisticType == StatisticType.ItemCount)).Value);
    }

    [Fact]
    public async Task ConcurrentDeletes_KeepOneCollectionAndMatchingStatistics()
    {
        var barrier = new BothCounted();
        await using var app = new MembershipWebApplicationFactory(fixture.ConnectionString);
        await using var observed = app.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.AddDbContextFactory<AppDbContext>(options => options.UseNpgsql(fixture.ConnectionString).AddInterceptors(barrier))));
        using var first = Authenticate(observed.CreateClient());
        using var second = Authenticate(observed.CreateClient());
        var responses = await Task.WhenAll(first.DeleteAsync("/api/collections/1"), second.DeleteAsync("/api/collections/2"))
            .WaitAsync(TimeSpan.FromSeconds(20));
        try
        {
            Assert.Contains(responses, response => response.StatusCode == HttpStatusCode.NoContent);
            Assert.Contains(responses, response => response.StatusCode == HttpStatusCode.Conflict);
            await using var check = fixture.CreateContext();
            Assert.Equal(1, await check.Collections.CountAsync());
            Assert.Equal(1, (await check.WorkspaceStatistics.SingleAsync(s => s.StatisticType == StatisticType.CollectionCount)).Value);
        }
        finally { foreach (var response in responses) response.Dispose(); }
    }

    private static HttpClient Authenticate(HttpClient client)
    {
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, "1");
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, "1");
        return client;
    }

    private sealed class BeforeRead(Func<string, Task> before) : DbCommandInterceptor
    {
        public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            await before(command.CommandText);
            return result;
        }
    }

    private sealed class BothCounted : DbCommandInterceptor
    {
        private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _count;
        public override async ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData eventData,
            DbDataReader result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("count(*)") && command.CommandText.Contains("FROM \"Collections\""))
            {
                if (Interlocked.Increment(ref _count) == 2) _ready.TrySetResult();
                await _ready.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
            }
            return result;
        }
    }
}
