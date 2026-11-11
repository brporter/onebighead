using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class PublicCatalogSnapshotTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var db = fixture.CreateContext();
        db.Workspaces.Add(new Workspace { Id = 1, Name = "Gallery", Slug = "gallery" });
        db.Collections.Add(new Collection { Id = 1, WorkspaceId = 1, Name = "Collection", Visibility = Visibility.Public });
        db.Categories.Add(new Category { Id = 1, CollectionId = 1, WorkspaceId = 1, Name = "Private category", Visibility = Visibility.Private });
        db.Items.Add(new Item { Id = 1, CollectionId = 1, WorkspaceId = 1, Name = "Private item", Visibility = Visibility.Private });
        await db.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData("Items", "/items")]
    [InlineData("Categories", "")]
    public async Task AtomicPublicationChange_NeverCombinesAnOldPublicParentWithNewlyPublishedChildren(string table, string suffix)
    {
        var change = new BeforeRead(table, async () =>
        {
            await using var db = fixture.CreateContext();
            (await db.Collections.SingleAsync()).Visibility = Visibility.Private;
            (await db.Categories.SingleAsync()).Visibility = Visibility.Public;
            (await db.Items.SingleAsync()).Visibility = Visibility.Public;
            await db.SaveChangesAsync();
        });
        await using var app = new MembershipWebApplicationFactory(fixture.ConnectionString);
        await using var observed = app.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.AddDbContextFactory<AppDbContext>(options => options.UseNpgsql(fixture.ConnectionString).AddInterceptors(change))));
        using var client = observed.CreateClient();
        var url = "/api/public/gallery/collections/1" + suffix;
        using var first = await client.GetAsync(url);
        first.EnsureSuccessStatusCode();
        Assert.True(change.Triggered);
        var body = await first.Content.ReadFromJsonAsync<JsonElement>();
        var entries = table == "Items" ? body : body.GetProperty("categories");
        // These children were never publicly visible: their collection was hidden
        // in the same commit that changed their own visibility to public.
        Assert.Empty(entries.EnumerateArray());
        using var next = await client.GetAsync(url);
        Assert.Equal(HttpStatusCode.NotFound, next.StatusCode);
    }

    private sealed class BeforeRead(string table, Func<Task> change) : DbCommandInterceptor
    {
        public bool Triggered { get; private set; }
        public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            if (!Triggered && command.CommandText.Contains($"FROM \"{table}\""))
            {
                Triggered = true;
                await change();
            }
            return result;
        }
    }
}
