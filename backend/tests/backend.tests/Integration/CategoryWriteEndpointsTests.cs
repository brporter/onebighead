using System.Net;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class CategoryWriteEndpointsTests(CustomWebApplicationFactory factory) : IntegrationTestBase(factory)
{
    [Fact]
    public async Task Create_LocationLoadsCommittedCategory_AndUpdateReturnsSameNormalizedContract()
    {
        var response = await PostJsonAsync("/api/categories", new CreateCategoryRequest
        { CollectionId = 1, Name = "  New entry  ", ItemTemplateIds = [2, 1, 2] });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = (await DeserializeResponseAsync<CategoryResponse>(response))!;
        Assert.Equal("New entry", created.Name);
        Assert.Equal([2, 1], created.ItemTemplateIds);
        Assert.NotNull(response.Headers.Location);
        var detailResponse = await Client.GetAsync(response.Headers.Location);
        detailResponse.EnsureSuccessStatusCode();
        var detail = (await DeserializeResponseAsync<CategoryResponse>(detailResponse))!;
        Assert.Equal(created.CategoryId, detail.CategoryId);
        Assert.Equal(created.ItemTemplateIds, detail.ItemTemplateIds);

        var updateResponse = await PutJsonAsync($"/api/categories/{created.CategoryId}", new UpdateCategoryRequest
        { Name = "  Edited entry  ", Description = "Updated", ItemTemplateIds = [] });
        updateResponse.EnsureSuccessStatusCode();
        var edited = (await DeserializeResponseAsync<CategoryResponse>(updateResponse))!;
        Assert.Equal("Edited entry", edited.Name);
        Assert.Equal("Updated", edited.Description);
        Assert.Empty(edited.ItemTemplateIds);
        var reorderResponse = await PutJsonAsync("/api/categories/reorder", new ReorderCategoriesRequest
        { Categories = [new() { CategoryId = created.CategoryId, SortOrder = 7 }] });
        reorderResponse.EnsureSuccessStatusCode();
        Assert.Equal(7, (await DeserializeResponseAsync<List<CategoryResponse>>(reorderResponse))!
            .Single(category => category.CategoryId == created.CategoryId).SortOrder);
    }

    [Fact]
    public async Task InvalidEdit_DoesNotPersistNameParentOrAssignments()
    {
        var response = await PostJsonAsync("/api/categories", new CreateCategoryRequest { CollectionId = 1, Name = "Original", ItemTemplateIds = [1] });
        response.EnsureSuccessStatusCode();
        var created = (await DeserializeResponseAsync<CategoryResponse>(response))!;
        var cycleResponse = await PutJsonAsync($"/api/categories/{created.CategoryId}", new UpdateCategoryRequest
        { Name = "Rejected", ParentCategoryId = created.CategoryId, ItemTemplateIds = [] });
        Assert.Equal(HttpStatusCode.BadRequest, cycleResponse.StatusCode);
        var detail = (await DeserializeResponseAsync<CategoryResponse>(await Client.GetAsync($"/api/categories/{created.CategoryId}")))!;
        Assert.Equal("Original", detail.Name);
        Assert.Null(detail.ParentCategoryId);
        Assert.Equal([1], detail.ItemTemplateIds);
        Assert.Equal(HttpStatusCode.BadRequest, (await PostJsonAsync("/api/categories", new CreateCategoryRequest
        { CollectionId = 1, Name = " unassigned items " })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await PostJsonAsync("/api/categories", new CreateCategoryRequest
        { CollectionId = 1, Name = "Invalid template", ItemTemplateIds = [999] })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await PutJsonAsync("/api/categories/reorder", new ReorderCategoriesRequest
        { Categories = [new() { CategoryId = 1, SortOrder = 3 }] })).StatusCode);
    }

    [Fact]
    public async Task Delete_ReturnsConflictForForeignReferences_WithoutChangingForeignItem()
    {
        await Factory.SeedDatabaseAsync(context =>
        {
            context.Categories.Add(new Category { Id = 100, WorkspaceId = 1, CollectionId = 1, Name = "Referenced" });
            context.Workspaces.Add(new Workspace { Id = 100, Name = "Foreign" });
            context.Collections.Add(new Collection { Id = 100, WorkspaceId = 100, Name = "Foreign", Slug = "foreign" });
            context.Items.Add(new Item { Id = 100, WorkspaceId = 100, CollectionId = 100, CategoryId = 100, Name = "Foreign reference" });
        });
        Assert.Equal(HttpStatusCode.Conflict, (await Client.DeleteAsync("/api/categories/100")).StatusCode);
        await using var context = GetDbContext();
        Assert.NotNull(await context.Categories.FindAsync(100));
        Assert.Equal(100, (await context.Items.FindAsync(100))!.CategoryId);
    }
}
