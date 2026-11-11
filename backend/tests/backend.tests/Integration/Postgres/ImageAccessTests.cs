using System.Net;
using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using OneBigHead.Server.Services.Images;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class ImageAccessTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private static readonly Guid Key = Guid.Parse("adc2002e-1675-4c16-bc57-853cfec5ee7a");
    private static readonly byte[] Data = [1, 2, 3, 4];
    private static string Url => $"/api/images/{Key}";

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var db = fixture.CreateContext();
        db.Workspaces.AddRange(new Workspace { Id = 1, Name = "Owner", Slug = "owner" },
            new Workspace { Id = 2, Name = "Other", Slug = "other" });
        db.Users.AddRange(new User { Id = 1, Email = "member@example.test", ActiveWorkspaceId = 1 },
            new User { Id = 2, Email = "removed@example.test", ActiveWorkspaceId = 2 });
        db.WorkspaceUsers.AddRange(new WorkspaceUser { UserId = 1, WorkspaceId = 1 },
            new WorkspaceUser { UserId = 2, WorkspaceId = 2 });
        db.Collections.AddRange(new Collection { Id = 1, WorkspaceId = 1, Name = "Collection", Visibility = Visibility.Public },
            new Collection { Id = 2, WorkspaceId = 2, Name = "Other", Visibility = Visibility.Public });
        db.Categories.AddRange(new Category { Id = 1, WorkspaceId = 1, CollectionId = 1, Name = "Parent", Visibility = Visibility.Public },
            new Category { Id = 2, WorkspaceId = 1, CollectionId = 1, ParentCategoryId = 1, Name = "Child", Visibility = Visibility.Public },
            new Category { Id = 3, WorkspaceId = 2, CollectionId = 2, Name = "Foreign", Visibility = Visibility.Public });
        db.Items.Add(new Item { Id = 1, WorkspaceId = 1, CollectionId = 1, CategoryId = 2, Name = "Item",
            Visibility = Visibility.Public, Images = [new ItemImage(Url, "Photo")] });
        db.StoredImages.Add(new StoredImage { Id = Key, WorkspaceId = 1, FileName = "photo.png", ContentType = "image/png", Data = Data });
        await db.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData("public-item", true)]
    [InlineData("public-hero", true)]
    [InlineData("no-category", true)]
    [InlineData("shared-visible-reference", true)]
    [InlineData("shared-second-collection", true)]
    [InlineData("private-item", false)]
    [InlineData("private-category", false)]
    [InlineData("private-ancestor", false)]
    [InlineData("private-collection", false)]
    [InlineData("private-hero", false)]
    [InlineData("foreign-hero", false)]
    [InlineData("deleted-workspace", false)]
    [InlineData("no-public-slug", false)]
    [InlineData("empty-public-slug", false)]
    [InlineData("whitespace-public-slug", false)]
    [InlineData("unattached", false)]
    [InlineData("foreign-reference", false)]
    [InlineData("foreign-collection", false)]
    [InlineData("foreign-category", false)]
    [InlineData("foreign-ancestor", false)]
    [InlineData("category-cycle", false)]
    [InlineData("external-url", false)]
    [InlineData("missing-image", false)]
    public async Task AnonymousReads_RequireACurrentPublicReference(string state, bool visible)
    {
        await ChangeState(state);
        await using var app = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var client = app.CreateClient();
        using var response = await client.GetAsync(Url);
        Assert.Equal(visible ? HttpStatusCode.OK : HttpStatusCode.NotFound, response.StatusCode);
        if (visible)
        {
            Assert.Equal(Data, await response.Content.ReadAsByteArrayAsync());
            Assert.Equal("image/png", response.Content.Headers.ContentType!.MediaType);
        }
    }

    [Theory]
    [InlineData("1", HttpStatusCode.OK)]
    [InlineData("2", HttpStatusCode.NotFound)]
    public async Task PrivateReads_RequireCurrentMembershipRatherThanAWorkspaceClaim(string userId, HttpStatusCode expected)
    {
        await ChangeState("private-item");
        await using var app = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var client = app.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, userId);
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, "1");
        using var response = await client.GetAsync(Url);
        Assert.Equal(expected, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
    }

    [Fact]
    public async Task HidingAnItem_RevokesTheSamePublicImageUrlWithoutCacheReuse()
    {
        await using var app = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var client = app.CreateClient();
        using var first = await client.GetAsync(Url);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.True(first.Headers.CacheControl?.NoStore);
        await ChangeState("private-item");
        using var second = await client.GetAsync(Url);
        Assert.Equal(HttpStatusCode.NotFound, second.StatusCode);
        Assert.True(second.Headers.CacheControl?.NoStore);
    }

    [Theory]
    [InlineData(null, 1, false, false)]
    [InlineData(0, 1, false, false)]
    [InlineData(-1, 1, false, false)]
    [InlineData(1, null, false, false)]
    [InlineData(1, 2, false, false)]
    [InlineData(1, 1, true, false)]
    [InlineData(1, 1, false, true)]
    public async Task PrivateReader_RequiresAnActiveAccountAndMembershipEvenWithoutAPublicSlug(int? userId, int? workspaceId, bool deleted, bool allowed)
    {
        await ChangeState("private-item");
        await using (var db = fixture.CreateContext())
        {
            (await db.Workspaces.SingleAsync(w => w.Id == 1)).Slug = null;
            (await db.Users.SingleAsync(u => u.Id == 1)).IsDeleted = deleted;
            await db.SaveChangesAsync();
        }
        var result = await Reader().ReadAsync(Key, userId, workspaceId, CancellationToken.None);
        Assert.Equal(allowed, result is not null);
    }

    [Fact]
    public async Task MemberOfAnotherWorkspace_CanStillReadAPublishedImage()
    {
        var result = await Reader().ReadAsync(Key, 2, 2, CancellationToken.None);
        Assert.NotNull(result);
        Assert.Equal(Data, result.Data);
    }

    [Fact]
    public async Task Cancellation_PropagatesToDatabaseReads()
    {
        using var cancellation = new CancellationTokenSource();
        var reader = Reader(new BeforeRead(token =>
        {
            Assert.Equal(cancellation.Token, token);
            cancellation.Cancel();
            token.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => reader.ReadAsync(Key, null, null, cancellation.Token));
    }

    [Fact]
    public async Task StorageFailure_PropagatesInsteadOfReturningImageBytes()
    {
        var failure = new InvalidOperationException("Image storage unavailable");
        var reader = Reader(new BeforeRead(_ => throw failure));
        Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() => reader.ReadAsync(Key, null, null, CancellationToken.None)));
    }

    [Fact]
    public async Task ConcurrentPublicationChange_UsesOneSnapshotAndTheNextRequestSeesTheChange()
    {
        var reads = 0;
        var reader = Reader(new BeforeRead(async _ =>
        {
            if (++reads == 2) await ChangeState("private-ancestor");
        }));
        // An already-running read completes against its original snapshot.
        Assert.NotNull(await reader.ReadAsync(Key, null, null, CancellationToken.None));
        Assert.True(reads > 2);
        Assert.Null(await Reader().ReadAsync(Key, null, null, CancellationToken.None));
    }

    private ImageReader Reader(params IInterceptor[] interceptors) => new(new TestDbContextFactory(
        new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString).AddInterceptors(interceptors).Options), new VisibilityService());

    private sealed class BeforeRead(Func<CancellationToken, Task> before) : DbCommandInterceptor
    {
        public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            await before(cancellationToken);
            return result;
        }
    }

    private async Task ChangeState(string state)
    {
        await using var db = fixture.CreateContext();
        var item = await db.Items.SingleAsync();
        switch (state)
        {
            case "public-hero":
                item.Images = [];
                (await db.Collections.SingleAsync(c => c.Id == 1)).HeroImageUrl = Url;
                break;
            case "no-category": item.CategoryId = null; break;
            case "shared-visible-reference":
                item.Visibility = Visibility.Private;
                db.Items.Add(new Item { Id = 2, WorkspaceId = 1, CollectionId = 1, Name = "Shared", Visibility = Visibility.Public,
                    Images = [new ItemImage(Url, "Photo")] });
                break;
            case "shared-second-collection":
                (await db.Categories.SingleAsync(c => c.Id == 2)).Visibility = Visibility.Private;
                db.Collections.Add(new Collection { Id = 3, WorkspaceId = 1, Name = "Another public collection", Slug = "second", Visibility = Visibility.Public });
                db.Items.Add(new Item { Id = 2, WorkspaceId = 1, CollectionId = 3, Name = "Visible", Visibility = Visibility.Public,
                    Images = [new ItemImage(Url, "Shared")] });
                break;
            case "private-item": item.Visibility = Visibility.Private; break;
            case "private-category": (await db.Categories.SingleAsync(c => c.Id == 2)).Visibility = Visibility.Private; break;
            case "private-ancestor": (await db.Categories.SingleAsync(c => c.Id == 1)).Visibility = Visibility.Private; break;
            case "private-collection": (await db.Collections.SingleAsync(c => c.Id == 1)).Visibility = Visibility.Private; break;
            case "private-hero":
                item.Images = [];
                var collection = await db.Collections.SingleAsync(c => c.Id == 1);
                collection.HeroImageUrl = Url;
                collection.Visibility = Visibility.Private;
                break;
            case "foreign-hero":
                item.Images = [];
                (await db.Collections.SingleAsync(c => c.Id == 2)).HeroImageUrl = Url;
                break;
            case "deleted-workspace": (await db.Workspaces.SingleAsync(w => w.Id == 1)).IsDeleted = true; break;
            case "no-public-slug": (await db.Workspaces.SingleAsync(w => w.Id == 1)).Slug = null; break;
            case "empty-public-slug": (await db.Workspaces.SingleAsync(w => w.Id == 1)).Slug = ""; break;
            case "whitespace-public-slug": (await db.Workspaces.SingleAsync(w => w.Id == 1)).Slug = " "; break;
            case "unattached": item.Images = []; break;
            case "foreign-reference": item.WorkspaceId = 2; item.CollectionId = 2; item.CategoryId = null; break;
            case "foreign-collection": item.CollectionId = 2; item.CategoryId = null; break;
            case "foreign-category": item.CategoryId = 3; break;
            case "foreign-ancestor": (await db.Categories.SingleAsync(c => c.Id == 1)).ParentCategoryId = 3; break;
            case "category-cycle": (await db.Categories.SingleAsync(c => c.Id == 1)).ParentCategoryId = 2; break;
            case "external-url": item.Images = [new ItemImage("https://elsewhere.example" + Url, "External")]; break;
            case "missing-image": db.StoredImages.Remove(await db.StoredImages.SingleAsync()); break;
        }
        await db.SaveChangesAsync();
    }
}
