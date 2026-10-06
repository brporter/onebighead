using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class StatisticsConcurrencyTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var context = fixture.CreateContext();
        context.Workspaces.Add(new Workspace { Id = 1, Name = "Workspace" });
        context.Users.Add(new User { Id = 1, ActiveWorkspaceId = 1, Email = "test@example.com" });
        context.Collections.Add(new Collection { Id = 1, WorkspaceId = 1, Name = "Collection", Slug = "collection" });
        context.Items.Add(new Item { Id = 1, CollectionId = 1, WorkspaceId = 1, Name = "Item" });
        await context.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task ConcurrentIncrements_DoNotLoseUpdates()
    {
        var factory = fixture.CreateContextFactory();
        var workspaces = new WorkspaceStatisticsRepository(factory);
        var collections = new CollectionStatisticsRepository(factory);
        await Task.WhenAll(Enumerable.Range(0, 20).Select(async _ =>
        {
            await workspaces.IncrementAsync(1, StatisticType.CollectionCount, 2);
            await collections.IncrementAsync(1, CollectionStatisticType.ItemCount, 3);
            await collections.IncrementItemViewAsync(1, 1);
        }));
        Assert.Equal(40, (await workspaces.GetAggregatesAsync(1))[StatisticType.CollectionCount]);
        Assert.Equal(60, (await collections.GetAggregatesAsync(1))[CollectionStatisticType.ItemCount]);
        Assert.Equal(20, Assert.Single(await collections.GetTopViewedItemsAsync(1)).ViewCount);
    }

    [Fact]
    public async Task ConcurrentRevocations_KeepNewestCutoff()
    {
        var repository = new TokenRevocationRepository(fixture.CreateContextFactory());
        var latest = new DateTime(2026, 10, 5, 12, 0, 0, DateTimeKind.Utc);
        await Task.WhenAll(Enumerable.Range(0, 20).Select(i => repository.UpsertAsync(1, latest.AddMinutes(-i))));
        Assert.Equal(latest, await repository.GetRevokedAtUtcAsync(1));
        await using var context = fixture.CreateContext();
        Assert.Equal(1, await context.TokenRevocations.CountAsync());
    }

    [Fact]
    public async Task WorkspaceStatistics_SeparateDailyAndAggregateCountersAndClampDecrements()
    {
        var repository = new WorkspaceStatisticsRepository(fixture.CreateContextFactory());
        var date = new DateOnly(2026, 10, 5);
        await repository.IncrementAsync(1, StatisticType.CollectionCount, 3);
        await repository.IncrementAsync(1, StatisticType.CollectionCount, 7, date);
        await repository.IncrementAsync(2, StatisticType.CollectionCount, 10);
        await repository.DecrementAsync(1, StatisticType.CollectionCount, 2);
        Assert.Equal(1, (await repository.GetAggregatesAsync(1))[StatisticType.CollectionCount]);
        await repository.DecrementAsync(1, StatisticType.CollectionCount, 5);
        Assert.Equal(0, (await repository.GetAggregatesAsync(1))[StatisticType.CollectionCount]);
        Assert.Equal(7, Assert.Single(await repository.GetDailyAsync(1, StatisticType.CollectionCount, date, date)).Value);
        Assert.Empty(await repository.GetDailyAsync(1, StatisticType.CollectionCount, date.AddDays(1), date.AddDays(2)));
        Assert.Equal(10, (await repository.GetAggregatesAsync(2))[StatisticType.CollectionCount]);
    }

    [Fact]
    public async Task Upsert_DoesNotSwallowForeignKeyErrors()
    {
        var repository = new CollectionStatisticsRepository(fixture.CreateContextFactory());
        var error = await Assert.ThrowsAsync<Npgsql.PostgresException>(() => repository.IncrementAsync(999, CollectionStatisticType.ItemCount));
        Assert.Equal(Npgsql.PostgresErrorCodes.ForeignKeyViolation, error.SqlState);
    }
}
