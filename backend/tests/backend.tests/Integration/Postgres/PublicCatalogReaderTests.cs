using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using OneBigHead.Server.Services.PublicCatalog;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class PublicCatalogReaderTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private static readonly Guid TemplateKey = Guid.Parse("03e8f296-090e-43f9-a52a-2736d150b82a");

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var db = fixture.CreateContext();
        db.Workspaces.AddRange(new Workspace { Id = 1, Name = "Gallery", Slug = "gallery" },
            new Workspace { Id = 2, Name = "Other", Slug = "other" },
            new Workspace { Id = 3, Name = "Deleted", Slug = "deleted", IsDeleted = true },
            new Workspace { Id = 4, Name = "Empty", Slug = "empty" },
            new Workspace { Id = 5, Name = "No collections", Slug = "empty-catalog" });
        db.Collections.AddRange(
            new Collection { Id = 1, WorkspaceId = 1, Name = "Bravo", Slug = "main", Description = "Description", HeroImageUrl = "/hero.png", Visibility = Visibility.Public },
            new Collection { Id = 2, WorkspaceId = 1, Name = "Private", Slug = "private", Visibility = Visibility.Private },
            new Collection { Id = 3, WorkspaceId = 2, Name = "Foreign", Slug = "foreign", Visibility = Visibility.Public },
            new Collection { Id = 4, WorkspaceId = 3, Name = "Deleted", Slug = "deleted", Visibility = Visibility.Public },
            new Collection { Id = 5, WorkspaceId = 1, Name = "Alpha", Slug = "empty", Visibility = Visibility.Public },
            new Collection { Id = 6, WorkspaceId = 4, Name = "Empty", Slug = "empty", Visibility = Visibility.Public });
        db.Categories.AddRange(
            Category(1, 1, 1, "Parent", Visibility.Public),
            Category(2, 1, 1, "Child", Visibility.Public, 1, 1),
            Category(3, 1, 1, "Private", Visibility.Private),
            Category(4, 1, 1, "Hidden descendant", Visibility.Public, 3),
            Category(5, 2, 3, "Foreign", Visibility.Public),
            new Category { Id = 6, WorkspaceId = 1, CollectionId = 1, Name = "Unassigned", IsSystem = true, Visibility = Visibility.Public, SortOrder = 2 },
            Category(7, 2, 1, "Foreign owner", Visibility.Public),
            Category(8, 1, 5, "Other collection", Visibility.Public));
        db.Items.AddRange(
            new Item { Id = 1, WorkspaceId = 1, CollectionId = 1, CategoryId = 2, Name = "Bravo", Summary = "Summary", Description = "Detail",
                Visibility = Visibility.Public, TemplateKey = TemplateKey, Properties = [new ItemProperty("General", "Condition", "Mint")],
                Images = [new ItemImage("/photo.png", "Photo")], UserFlag = UserFlag.Want },
            Item(2, 1, 1, null, "Alpha", Visibility.Public),
            Item(3, 1, 1, 2, "Private", Visibility.Private),
            Item(4, 1, 1, 4, "Hidden ancestor", Visibility.Public),
            Item(5, 2, 3, 5, "Foreign", Visibility.Public),
            Item(6, 2, 1, null, "Foreign owner", Visibility.Public),
            Item(7, 1, 1, 8, "Other collection category", Visibility.Public),
            Item(8, 1, 2, null, "Private collection", Visibility.Public),
            Item(9, 3, 4, null, "Deleted workspace", Visibility.Public),
            Item(10, 1, 1, 5, "Foreign category", Visibility.Public),
            Item(11, 1, 1, 7, "Category with foreign owner", Visibility.Public));
        db.ItemTemplates.AddRange(new ItemTemplate { Id = 1, Name = "System", TemplateKey = Guid.NewGuid() },
            new ItemTemplate { Id = 2, WorkspaceId = 1, Name = "Own", TemplateKey = TemplateKey },
            new ItemTemplate { Id = 3, WorkspaceId = 2, Name = "Foreign", TemplateKey = Guid.NewGuid() });
        db.CategoryItemTemplates.AddRange(new CategoryItemTemplate { CategoryId = 2, ItemTemplateId = 1, SortOrder = 1 },
            new CategoryItemTemplate { CategoryId = 2, ItemTemplateId = 2 },
            new CategoryItemTemplate { CategoryId = 2, ItemTemplateId = 3, SortOrder = -1 },
            new CategoryItemTemplate { CategoryId = 3, ItemTemplateId = 1 });
        await db.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Catalog_ProjectsVisibleCollectionsCategoriesAndOwnedOrSystemTemplatesInOrder()
    {
        var reader = Reader();
        var workspace = await reader.GetWorkspaceAsync("gallery", CancellationToken.None);
        Assert.Equal("Gallery", workspace!.Name);
        Assert.Equal("gallery", workspace.Slug);
        var collections = await reader.GetCollectionsAsync("gallery", CancellationToken.None);
        Assert.Equal(new[] { 5, 1 }, collections!.Select(c => c.Id));
        var detail = await reader.GetCollectionAsync("gallery", 1, CancellationToken.None);
        Assert.NotNull(detail);
        Assert.Equal("Bravo", detail.Collection.Name);
        Assert.Equal("main", detail.Collection.Slug);
        Assert.Equal("Description", detail.Collection.Description);
        Assert.Equal("/hero.png", detail.Collection.HeroImageUrl);
        Assert.Equal(new[] { 1, 2, 6 }, detail.Categories.Select(c => c.Id));
        Assert.Equal(new[] { 2, 1 }, detail.Categories[1].ItemTemplateIds);
        Assert.Equal(1, detail.Categories[1].ParentCategoryId);
        Assert.Empty(detail.Categories[0].ItemTemplateIds);
        Assert.True(detail.Categories[2].IsSystem);
        Assert.DoesNotContain(3, detail.Categories.SelectMany(c => c.ItemTemplateIds));
    }

    [Fact]
    public async Task ExistingEmptyResources_AreDistinctFromMissingResources()
    {
        var reader = Reader();
        Assert.Empty((await reader.GetCollectionsAsync("empty-catalog", CancellationToken.None))!);
        Assert.Empty((await reader.GetCollectionAsync("empty", 6, CancellationToken.None))!.Categories);
        Assert.Empty((await reader.GetItemsAsync("empty", 6, null, CancellationToken.None))!);
    }

    [Theory]
    [InlineData(null, new[] { 2, 1 })]
    [InlineData(2, new[] { 1 })]
    [InlineData(3, new int[] { })]
    [InlineData(5, new int[] { })]
    [InlineData(999, new int[] { })]
    public async Task Items_ApplyScopeAncestryAndCategoryFilter(int? categoryId, int[] expected)
    {
        var items = await Reader().GetItemsAsync("gallery", 1, categoryId, CancellationToken.None);
        Assert.NotNull(items);
        Assert.Equal(expected, items.Select(item => item.Id));
        if (categoryId is null)
        {
            Assert.Null(items[0].PrimaryImageUrl);
            Assert.Null(items[0].CategoryId);
            Assert.Equal("/photo.png", items[1].PrimaryImageUrl);
            Assert.Equal("Summary", items[1].Summary);
            Assert.Equal(2, items[1].CategoryId);
        }
    }

    [Fact]
    public async Task ItemDetails_IncludePublicPropertiesAndHandleUncategorizedItems()
    {
        var reader = Reader();
        var item = await reader.GetItemAsync("gallery", 1, CancellationToken.None);
        Assert.NotNull(item);
        Assert.Equal("Bravo", item.Name);
        Assert.Equal("Summary", item.Summary);
        Assert.Equal("Detail", item.Description);
        Assert.Equal("Child", item.CategoryName);
        Assert.Equal(TemplateKey, item.TemplateKey);
        var property = Assert.Single(item.Properties);
        Assert.Equal(("General", "Condition", "Mint"), (property.Category, property.Name, property.Value));
        var image = Assert.Single(item.Images);
        Assert.Equal(("/photo.png", "Photo"), (image.Url, image.Alt));
        var uncategorized = await reader.GetItemAsync("gallery", 2, CancellationToken.None);
        Assert.NotNull(uncategorized);
        Assert.Null(uncategorized.CategoryName);
        Assert.Null(uncategorized.CategoryId);
        Assert.Null(uncategorized.TemplateKey);
    }

    [Theory]
    [InlineData(3)] [InlineData(4)] [InlineData(5)] [InlineData(6)] [InlineData(7)]
    [InlineData(8)] [InlineData(9)] [InlineData(10)] [InlineData(11)] [InlineData(999)] [InlineData(-1)]
    public async Task PrivateForeignOrMissingItems_AreNotPublic(int id) =>
        Assert.Null(await Reader().GetItemAsync("gallery", id, CancellationToken.None));

    [Theory]
    [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(999)] [InlineData(-1)]
    public async Task PrivateForeignOrMissingCollections_AreNotPublic(int id)
    {
        Assert.Null(await Reader().GetCollectionAsync("gallery", id, CancellationToken.None));
        Assert.Null(await Reader().GetItemsAsync("gallery", id, null, CancellationToken.None));
    }

    [Theory]
    [InlineData(null)] [InlineData("")] [InlineData(" ")] [InlineData("missing")] [InlineData("deleted")]
    public async Task UnavailableWorkspace_HasNoPublicResources(string? slug)
    {
        var reader = Reader();
        Assert.Null(await reader.GetWorkspaceAsync(slug!, CancellationToken.None));
        Assert.Null(await reader.GetCollectionsAsync(slug!, CancellationToken.None));
        Assert.Null(await reader.GetCollectionAsync(slug!, 1, CancellationToken.None));
        Assert.Null(await reader.GetItemsAsync(slug!, 1, null, CancellationToken.None));
        Assert.Null(await reader.GetItemAsync(slug!, 1, CancellationToken.None));
    }

    [Theory]
    [InlineData("workspace")] [InlineData("collections")] [InlineData("collection")] [InlineData("items")] [InlineData("item")]
    public async Task EachRead_PropagatesCancellationAndStorageFailure(string operation)
    {
        using var cancellation = new CancellationTokenSource();
        var cancelled = Reader(new BeforeRead(token =>
        {
            Assert.Equal(cancellation.Token, token);
            cancellation.Cancel();
            token.ThrowIfCancellationRequested();
        }));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Read(cancelled, operation, cancellation.Token));
        var failure = new InvalidOperationException("Storage unavailable");
        var failing = Reader(new BeforeRead(_ => throw failure));
        Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() => Read(failing, operation, CancellationToken.None)));
    }

    [Fact]
    public async Task HttpContracts_ExposeOnlyPublicFieldsAndPreventResponseCaching()
    {
        await using var app = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var client = app.CreateClient();
        var cases = new[]
        {
            (Path: "gallery", Fields: "name,slug", List: false),
            (Path: "gallery/collections", Fields: "description,heroImageUrl,id,name,slug", List: true),
            (Path: "gallery/collections/1", Fields: "categories,collection", List: false),
            (Path: "gallery/collections/1/items", Fields: "categoryId,id,name,primaryImageUrl,summary", List: true),
            (Path: "gallery/items/1", Fields: "categoryId,categoryName,description,id,images,name,properties,summary,templateKey", List: false)
        };
        foreach (var test in cases)
        {
            using var response = await client.GetAsync("/api/public/" + test.Path);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.True(response.Headers.CacheControl?.NoStore);
            var body = await response.Content.ReadFromJsonAsync<JsonElement>();
            var fields = (test.List ? body[0] : body).EnumerateObject().Select(property => property.Name).Order();
            Assert.Equal(test.Fields.Split(','), fields);
            using var missing = await client.GetAsync("/api/public/" + test.Path.Replace("gallery", "missing"));
            Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
            Assert.True(missing.Headers.CacheControl?.NoStore);
        }
    }

    private PublicCatalogReader Reader(params IInterceptor[] interceptors) => new(new TestDbContextFactory(
        new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString).AddInterceptors(interceptors).Options), new VisibilityService());

    private static Task Read(IPublicCatalogReader reader, string operation, CancellationToken token) => operation switch
    {
        "workspace" => reader.GetWorkspaceAsync("gallery", token),
        "collections" => reader.GetCollectionsAsync("gallery", token),
        "collection" => reader.GetCollectionAsync("gallery", 1, token),
        "items" => reader.GetItemsAsync("gallery", 1, null, token),
        _ => reader.GetItemAsync("gallery", 1, token)
    };

    private static Category Category(int id, int workspaceId, int collectionId, string name, Visibility visibility, int? parent = null, int sort = 0) =>
        new() { Id = id, WorkspaceId = workspaceId, CollectionId = collectionId, Name = name, Visibility = visibility, ParentCategoryId = parent, SortOrder = sort };
    private static Item Item(int id, int workspaceId, int collectionId, int? categoryId, string name, Visibility visibility) =>
        new() { Id = id, WorkspaceId = workspaceId, CollectionId = collectionId, CategoryId = categoryId, Name = name, Visibility = visibility };

    private sealed class BeforeRead(Action<CancellationToken> before) : DbCommandInterceptor
    {
        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            before(cancellationToken);
            return ValueTask.FromResult(result);
        }
    }
}
