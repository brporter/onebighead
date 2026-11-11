using System.Net;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class CategoryReadEndpointsTests(CustomWebApplicationFactory factory) : IntegrationTestBase(factory)
{
    [Fact]
    public async Task ReadRoutes_ReturnActualCollectionVisibilityAndTemplates_WithoutForeignData()
    {
        await Factory.SeedDatabaseAsync(context =>
        {
            context.Collections.Add(new Collection
            {
                Id = 100, WorkspaceId = 1, Name = "Public collection", Slug = "public-read", Visibility = Visibility.Public
            });
            context.Workspaces.Add(new Workspace { Id = 100, Name = "Foreign" });
            context.Collections.Add(new Collection { Id = 101, WorkspaceId = 100, Name = "Foreign", Slug = "foreign-read" });
            context.Categories.AddRange(
                new Category { Id = 100, WorkspaceId = 1, CollectionId = 100, Name = "Public root", Visibility = Visibility.Public },
                new Category { Id = 101, WorkspaceId = 1, CollectionId = 100, Name = "Public child", ParentCategoryId = 100, Visibility = Visibility.Public },
                new Category { Id = 102, WorkspaceId = 1, CollectionId = 1, Name = "Hidden by collection", Visibility = Visibility.Public },
                new Category { Id = 103, WorkspaceId = 100, CollectionId = 101, Name = "Foreign category" });
            context.CategoryItemTemplates.AddRange(
                new CategoryItemTemplate { CategoryId = 100, ItemTemplateId = 2 },
                new CategoryItemTemplate { CategoryId = 102, ItemTemplateId = 1 });
        });

        var listResponse = await Client.GetAsync("/api/categories");
        listResponse.EnsureSuccessStatusCode();
        var categories = (await DeserializeResponseAsync<List<CategoryResponse>>(listResponse))!;
        Assert.True(categories.Single(category => category.CategoryId == 100).EffectiveIsPublic);
        Assert.True(categories.Single(category => category.CategoryId == 101).EffectiveIsPublic);
        Assert.False(categories.Single(category => category.CategoryId == 102).EffectiveIsPublic);
        Assert.Equal([2], categories.Single(category => category.CategoryId == 100).ItemTemplateIds);
        Assert.Equal([1], categories.Single(category => category.CategoryId == 102).ItemTemplateIds);
        Assert.DoesNotContain(categories, category => category.CategoryId == 103);

        var detailResponse = await Client.GetAsync("/api/categories/100");
        detailResponse.EnsureSuccessStatusCode();
        var detail = (await DeserializeResponseAsync<CategoryResponse>(detailResponse))!;
        Assert.True(detail.EffectiveIsPublic);
        Assert.Equal([2], detail.ItemTemplateIds);

        var inheritedResponse = await Client.GetAsync("/api/categories/101/templates");
        inheritedResponse.EnsureSuccessStatusCode();
        Assert.Equal([2], await DeserializeResponseAsync<List<int>>(inheritedResponse));
        Assert.Equal(HttpStatusCode.NotFound, (await Client.GetAsync("/api/categories?collectionId=101")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Client.GetAsync("/api/categories/103")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Client.GetAsync("/api/categories/103/templates")).StatusCode);
    }

    [Fact]
    public async Task CyclicData_DoesNotCrashPrivateReads_OrAppearInPublicCollection()
    {
        await Factory.SeedDatabaseAsync(context =>
        {
            context.Workspaces.Add(new Workspace { Id = 200, Name = "Public test workspace", Slug = "category-cycle-test" });
            context.Collections.Add(new Collection
            {
                Id = 200, WorkspaceId = 200, Name = "Collection", Slug = "cycle", Visibility = Visibility.Public
            });
            context.Categories.AddRange(
                new Category { Id = 200, WorkspaceId = 200, CollectionId = 200, Name = "Cycle A", ParentCategoryId = 201, Visibility = Visibility.Public },
                new Category { Id = 201, WorkspaceId = 200, CollectionId = 200, Name = "Cycle B", ParentCategoryId = 200, Visibility = Visibility.Public },
                new Category { Id = 202, WorkspaceId = 200, CollectionId = 200, Name = "Valid public root", Visibility = Visibility.Public });
        });

        using var workspaceClient = CreateClientForWorkspace(200, DefaultUserId);
        var privateResponse = await workspaceClient.GetAsync("/api/categories?collectionId=200");
        privateResponse.EnsureSuccessStatusCode();
        var categories = (await DeserializeResponseAsync<List<CategoryResponse>>(privateResponse))!;
        Assert.Equal(3, categories.Count);
        Assert.All(categories.Where(category => category.CategoryId != 202), category => Assert.False(category.EffectiveIsPublic));

        using var anonymous = CreateAnonymousClient();
        var publicResponse = await anonymous.GetAsync("/api/public/category-cycle-test/collections/200");
        publicResponse.EnsureSuccessStatusCode();
        var publicCollection = (await DeserializeResponseAsync<PublicCollectionDetailDto>(publicResponse))!;
        Assert.Equal(202, Assert.Single(publicCollection.Categories).Id);
    }
}
