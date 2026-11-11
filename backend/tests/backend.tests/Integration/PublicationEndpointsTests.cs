using System.Net;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class PublicationEndpointsTests(CustomWebApplicationFactory factory) : IntegrationTestBase(factory)
{
    [Fact]
    public async Task PublishAndUnpublish_PreserveTheWireContractAndRefreshItemVisibility()
    {
        await Factory.SeedDatabaseAsync(context => {
            context.Collections.Add(new Collection { Id = 101, WorkspaceId = 1, Name = "Second collection", Slug = "second" });
            context.Categories.Add(new Category { Id = 101, WorkspaceId = 1, CollectionId = 101, Name = "Classics" });
            context.Items.Add(new Item { Id = 101, WorkspaceId = 1, CollectionId = 101, CategoryId = 101, Name = "Dune" });
        });
        var entities = new List<EntityRef> { new() { Type = "item", Id = 101 } };
        var check = await PostJsonAsync("/api/workspaces/1/publish/preflight", new PreflightRequest { Entities = entities });
        check.EnsureSuccessStatusCode();
        var preflight = (await DeserializeResponseAsync<PreflightResponse>(check))!;
        Assert.False(preflight.Ready);
        Assert.Contains(preflight.Requirements, requirement => requirement is CollectionNotPublicRequirement { CollectionId: 101 });
        Assert.Contains(preflight.Requirements, requirement => requirement is CategoryNotPublicRequirement { CategoryId: 101 });
        var execute = await PostJsonAsync("/api/workspaces/1/publish/execute", new ExecuteRequest { Entities = entities, Resolutions = [
            new WorkspaceSlugResolution { Slug = "test-library" }, new CollectionNotPublicResolution { CollectionId = 101 }, new CategoryNotPublicResolution { CategoryId = 101 }
        ] });
        execute.EnsureSuccessStatusCode();
        var published = (await DeserializeResponseAsync<ExecuteResponse>(execute))!;
        Assert.True(published.Success);
        Assert.Equal(101, Assert.Single(published.Changed).Id);
        var detailResponse = await Client.GetAsync("/api/items/101");
        detailResponse.EnsureSuccessStatusCode();
        Assert.True((await DeserializeResponseAsync<Item>(detailResponse))!.EffectiveIsPublic);
        var listResponse = await Client.GetAsync("/api/items");
        listResponse.EnsureSuccessStatusCode();
        Assert.True((await DeserializeResponseAsync<List<Item>>(listResponse))!.Single(item => item.Id == 101).EffectiveIsPublic);

        var hide = new ExecuteRequest { Action = PublishAction.Unpublish, Entities = [new() { Type = "category", Id = 101 }], Resolutions = [
            new UnpublishWillHideChildrenResolution { EntityType = "collection", EntityId = 101, AffectedPublicItems = 1, AffectedPublicCategories = 0 }
        ] };
        var rejected = (await DeserializeResponseAsync<ExecuteResponse>(await PostJsonAsync("/api/workspaces/1/publish/execute", hide)))!;
        Assert.False(rejected.Success);
        Assert.IsType<UnpublishWillHideChildrenRequirement>(Assert.Single(rejected.Requirements!));
        hide.Resolutions = [new UnpublishWillHideChildrenResolution { EntityType = "category", EntityId = 101, AffectedPublicItems = 1, AffectedPublicCategories = 0 }];
        Assert.True((await DeserializeResponseAsync<ExecuteResponse>(await PostJsonAsync("/api/workspaces/1/publish/execute", hide)))!.Success);
        Assert.False((await DeserializeResponseAsync<Item>(await Client.GetAsync("/api/items/101")))!.EffectiveIsPublic);
    }

    [Theory]
    [InlineData("preflight")] [InlineData("execute")]
    public async Task InvalidMissingAndForeignRequests_UseHttpErrors(string action)
    {
        var url = $"/api/workspaces/1/publish/{action}";
        Assert.Equal(HttpStatusCode.BadRequest, (await PostJsonAsync(url, new { action = "publish", entities = Array.Empty<EntityRef>() })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await PostJsonAsync(url, new { action = "publish", entities = new object[] { new { type = "unknown", id = 1 } } })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await PostJsonAsync(url, new { action = "publish", entities = new object[] { new { type = "item", id = 999 } } })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await PostJsonAsync($"/api/workspaces/2/publish/{action}", new { action = "publish", entities = new object[] { new { type = "collection", id = 1 } } })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await PostJsonAsync(url, new { action = "publish", entities = (object?)null })).StatusCode);
    }
}
