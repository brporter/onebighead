using System.Net;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class ItemReadEndpointsTests(CustomWebApplicationFactory factory) : IntegrationTestBase(factory)
{
    [Fact]
    public async Task CategoryReads_KeepDescendantsAndPaginationInsideTheOwningCollection()
    {
        await Factory.SeedDatabaseAsync(context =>
        {
            context.Collections.AddRange(
                new Collection { Id = 10, WorkspaceId = 1, Name = "Library", Slug = "library", Visibility = Visibility.Public },
                new Collection { Id = 20, WorkspaceId = 1, Name = "Other", Slug = "other" });
            context.Categories.AddRange(
                new Category { Id = 101, WorkspaceId = 1, CollectionId = 10, Name = "Books", Visibility = Visibility.Public },
                new Category { Id = 102, WorkspaceId = 1, CollectionId = 10, ParentCategoryId = 101, Name = "Fiction", Visibility = Visibility.Public },
                new Category { Id = 103, WorkspaceId = 1, CollectionId = 10, ParentCategoryId = 102, Name = "Science fiction", Visibility = Visibility.Public },
                new Category { Id = 104, WorkspaceId = 1, CollectionId = 20, ParentCategoryId = 101, Name = "Invalid child" });
            context.Items.AddRange(
                new Item { Id = 103, WorkspaceId = 1, CollectionId = 10, CategoryId = 103, Name = "Dune", Visibility = Visibility.Public },
                new Item { Id = 102, WorkspaceId = 1, CollectionId = 10, CategoryId = 102, Name = "Fiction", Visibility = Visibility.Public },
                new Item { Id = 101, WorkspaceId = 1, CollectionId = 10, CategoryId = 101, Name = "Book", Visibility = Visibility.Public },
                new Item { Id = 104, WorkspaceId = 1, CollectionId = 20, CategoryId = 104, Name = "Wrong collection child" },
                new Item { Id = 105, WorkspaceId = 1, CollectionId = 20, CategoryId = 101, Name = "Wrong collection item" });
        });

        const string url = "/api/items?categoryId=101&includeDescendants=true";
        var response = await Client.GetAsync(url);
        response.EnsureSuccessStatusCode();
        var items = (await DeserializeResponseAsync<List<Item>>(response))!;
        Assert.Equal(new int?[] { 101, 102, 103 }, items.Select(item => item.Id));
        Assert.All(items, item => Assert.True(item.EffectiveIsPublic));
        var direct = (await DeserializeResponseAsync<List<Item>>(await Client.GetAsync("/api/items?categoryId=101")))!;
        Assert.Equal(101, Assert.Single(direct).Id);

        var zero = await Client.GetAsync(url + "&take=0");
        Assert.Empty((await DeserializeResponseAsync<List<Item>>(zero))!);
        Assert.Equal("3", Assert.Single(zero.Headers.GetValues("X-Total-Count")));
        var first = await Client.GetAsync(url + "&take=1");
        Assert.Equal(101, Assert.Single((await DeserializeResponseAsync<List<Item>>(first))!).Id);
        using var samePage = new HttpRequestMessage(HttpMethod.Get, url + "&take=1");
        samePage.Headers.IfNoneMatch.Add(first.Headers.ETag!);
        var cached = await Client.SendAsync(samePage);
        Assert.Equal(HttpStatusCode.NotModified, cached.StatusCode);
        Assert.Equal("3", Assert.Single(cached.Headers.GetValues("X-Total-Count")));
        using var nextPage = new HttpRequestMessage(HttpMethod.Get, url + "&skip=1&take=1");
        nextPage.Headers.IfNoneMatch.Add(first.Headers.ETag!);
        var second = await Client.SendAsync(nextPage);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(102, Assert.Single((await DeserializeResponseAsync<List<Item>>(second))!).Id);
        Assert.NotEqual(first.Headers.ETag, second.Headers.ETag);
        Assert.Empty((await DeserializeResponseAsync<List<Item>>(await Client.GetAsync("/api/items?categoryId=99999&includeDescendants=true")))!);
    }

    [Theory]
    [InlineData("skip=-1")]
    [InlineData("take=-1")]
    public async Task InvalidPagination_ReturnsBadRequest(string query)
    {
        Assert.Equal(HttpStatusCode.BadRequest, (await Client.GetAsync("/api/items?" + query)).StatusCode);
    }

    [Fact]
    public async Task Editing_CannotChangeCollectionAndReturnsCurrentVisibility()
    {
        await Factory.SeedDatabaseAsync(context =>
        {
            context.Collections.AddRange(
                new Collection { Id = 30, WorkspaceId = 1, Name = "Original", Slug = "original", Visibility = Visibility.Public },
                new Collection { Id = 40, WorkspaceId = 1, Name = "Destination", Slug = "destination", Visibility = Visibility.Public });
            context.Categories.Add(new Category { Id = 401, WorkspaceId = 1, CollectionId = 40, Name = "Foreign category", Visibility = Visibility.Public });
            context.Items.Add(new Item { Id = 301, WorkspaceId = 1, CollectionId = 30, Name = "Original item", Visibility = Visibility.Public });
        });
        var rejected = await PutJsonAsync("/api/items/301", new UpdateItemRequest { Name = "Moved", CollectionId = 40, CategoryId = 401 });
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        rejected = await PutJsonAsync("/api/items/301", new UpdateItemRequest { Name = "Invalid category", CollectionId = 30, CategoryId = 401 });
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        var unchanged = (await DeserializeResponseAsync<Item>(await Client.GetAsync("/api/items/301")))!;
        Assert.Equal("Original item", unchanged.Name);
        Assert.Equal(30, unchanged.CollectionId);
        Assert.Null(unchanged.CategoryId);

        var saved = await PutJsonAsync("/api/items/301", new UpdateItemRequest { Name = "Edited", CollectionId = 30 });
        saved.EnsureSuccessStatusCode();
        var edited = (await DeserializeResponseAsync<Item>(saved))!;
        Assert.Equal("Edited", edited.Name);
        Assert.True(edited.EffectiveIsPublic);
        var created = await PostJsonAsync("/api/items", new CreateItemRequest { Name = "New public item", CollectionId = 30 });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.True((await DeserializeResponseAsync<Item>(created))!.EffectiveIsPublic);
    }
}
