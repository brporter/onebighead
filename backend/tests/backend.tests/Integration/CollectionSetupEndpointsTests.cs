using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class CollectionSetupEndpointsTests(CustomWebApplicationFactory factory) : IntegrationTestBase(factory)
{
    [Fact]
    public async Task Setup_PreservesPreviewRelationshipsOrderAndPrivateVisibility()
    {
        var theme = new CollectionTheme
        {
            Name = "Ordered theme",
            ThemeTemplates = [new() { ItemTemplateId = 2 }],
            ThemeCategories = [new() { Name = "Child", ParentName = " Root ", Description = "Details", SortOrder = 3 },
                new() { Name = "Root", SortOrder = 7 }, new() { Name = "Empty parent", ParentName = " ", SortOrder = 10 }]
        };
        await Factory.SeedDatabaseAsync(context => { context.CollectionThemes.Add(theme); });
        var preview = (await DeserializeResponseAsync<CollectionThemeDto>(await Client.GetAsync($"/api/themes/{theme.Id}")))!;
        Assert.Equal([3, 7, 10], preview.Categories.Select(category => category.SortOrder));
        var response = await Create(theme.Id);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var result = (await DeserializeResponseAsync<Collection>(response))!;
        var collectionId = result.Id;
        var workspaceId = result.WorkspaceId;
        Assert.Equal(Visibility.Private, result.Visibility);
        Assert.NotNull(response.Headers.Location);
        (await Client.GetAsync(response.Headers.Location)).EnsureSuccessStatusCode();
        using var reader = CreateClientForWorkspace(workspaceId, DefaultUserId);
        var categories = (await DeserializeResponseAsync<List<CategoryResponse>>(
            await reader.GetAsync($"/api/categories?collectionId={collectionId}")))!;
        var selected = categories.Where(category => !category.IsSystem).ToList();
        Assert.Equal(preview.Categories.Select(category => category.Name), selected.Select(category => category.Name));
        Assert.Equal(preview.Categories.Select(category => category.SortOrder), selected.Select(category => category.SortOrder));
        Assert.Equal(selected.Single(category => category.Name == "Root").CategoryId,
            selected.Single(category => category.Name == "Child").ParentCategoryId);
        Assert.Null(selected.Single(category => category.Name == "Empty parent").ParentCategoryId);
        Assert.All(categories, category => { Assert.Equal(workspaceId, category.WorkspaceId); Assert.Equal(collectionId, category.CollectionId); Assert.False(category.EffectiveIsPublic); });
    }

    [Theory]
    [InlineData("case")]
    [InlineData("cycle")]
    [InlineData("duplicate")]
    public async Task InvalidTheme_ReturnsUsefulErrorWithoutSavingPartialSetup(string kind)
    {
        var theme = new CollectionTheme
        {
            Name = "Invalid theme",
            ThemeCategories = [new() { Name = "Root" }, new()
            { Name = kind == "duplicate" ? " Root " : "Child", ParentName = kind == "case" ? "root" : "Child" }]
        };
        await Factory.SeedDatabaseAsync(context => { context.CollectionThemes.Add(theme); });
        await using var before = GetDbContext();
        var collectionCount = await before.Collections.CountAsync();
        var categoryCount = await before.Categories.CountAsync();
        var workspaceCount = await before.Workspaces.CountAsync();
        var activeWorkspaceId = (await before.Users.AsNoTracking().SingleAsync(user => user.Id == DefaultUserId)).ActiveWorkspaceId;
        var response = await Create(theme.Id);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("The selected theme", await response.Content.ReadAsStringAsync());
        Assert.False(response.Headers.Contains("Set-Cookie"));
        await using var after = GetDbContext();
        Assert.Equal(collectionCount, await after.Collections.CountAsync());
        Assert.Equal(categoryCount, await after.Categories.CountAsync());
        Assert.Equal(workspaceCount, await after.Workspaces.CountAsync());
        Assert.Equal(activeWorkspaceId, (await after.Users.SingleAsync(user => user.Id == DefaultUserId)).ActiveWorkspaceId);
    }

    private Task<HttpResponseMessage> Create(int themeId) => Client.PostAsJsonAsync("/api/collections/setup", new SetupCollectionRequest
        { Name = "Collection", Description = "Description", HeroImageUrl = "/image.jpg", ThemeId = themeId }, JsonOptions);
}
