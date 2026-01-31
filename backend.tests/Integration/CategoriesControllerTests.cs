using System.Net;
using System.Net.Http.Json;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class CategoriesControllerTests : IntegrationTestBase
{
    public CategoriesControllerTests(CustomWebApplicationFactory factory)
        : base(factory)
    {
    }

    #region GET /api/categories

    [Fact]
    public async Task GetCategories_WithCollectionId_ReturnsCategories()
    {
        // Arrange - The base setup creates one system category
        var cat1 = await CreateTestCategory("GetCategories User Category 1");
        var cat2 = await CreateTestCategory("GetCategories User Category 2");

        // Act
        var response = await Client.GetAsync("/api/categories?collectionId=1");

        // Assert
        response.EnsureSuccessStatusCode();
        var categories = await DeserializeResponseAsync<List<Category>>(response);
        Assert.NotNull(categories);
        // Verify system category and our created categories exist
        Assert.Contains(categories, c => c.IsSystem && c.Name == "Unassigned Items");
        Assert.Contains(categories, c => c.Id == cat1.Id);
        Assert.Contains(categories, c => c.Id == cat2.Id);
    }

    [Fact]
    public async Task GetCategories_WithHierarchy_ReturnsNestedStructure()
    {
        // Arrange - Create parent and child categories
        var parentCategory = await CreateTestCategory("Parent");
        await CreateTestCategory("Child", parentCategoryId: parentCategory.Id);

        // Act
        var response = await Client.GetAsync("/api/categories?collectionId=1");

        // Assert
        response.EnsureSuccessStatusCode();
        var categories = await DeserializeResponseAsync<List<Category>>(response);
        var child = categories!.FirstOrDefault(c => c.Name == "Child");
        Assert.NotNull(child);
        Assert.Equal(parentCategory.Id, child.ParentCategoryId);
    }

    [Fact]
    public async Task GetCategories_Unauthenticated_ReturnsUnauthorized()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();

        // Act
        var response = await anonClient.GetAsync("/api/categories?collectionId=1");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    #endregion

    #region GET /api/categories/{id}

    [Fact]
    public async Task GetCategory_ExistingId_ReturnsCategory()
    {
        // Arrange
        var category = await CreateTestCategory("Specific Category");

        // Act
        var response = await Client.GetAsync($"/api/categories/{category.Id}");

        // Assert
        response.EnsureSuccessStatusCode();
        var returned = await DeserializeResponseAsync<Category>(response);
        Assert.NotNull(returned);
        Assert.Equal("Specific Category", returned.Name);
    }

    [Fact]
    public async Task GetCategory_NonExistentId_ReturnsNotFound()
    {
        // Act
        var response = await Client.GetAsync("/api/categories/99999");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GetCategory_OtherTenantCategory_ReturnsNotFound()
    {
        // Arrange
        await Factory.SeedDatabaseAsync(context =>
        {
            var tenant = new Tenant { Id = 20, Name = "Other" };
            context.Tenants.Add(tenant);

            var collection = new Collection
            {
                Id = 20,
                TenantId = 20,
                Name = "Other Collection",
                Slug = "other"
            };
            context.Collections.Add(collection);

            var category = new Category
            {
                Id = 2000,
                TenantId = 20,
                CollectionId = 20,
                Name = "Other Category"
            };
            context.Categories.Add(category);
        });

        // Act
        var response = await Client.GetAsync("/api/categories/2000");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    #endregion

    #region POST /api/categories

    [Fact]
    public async Task CreateCategory_ValidRequest_CreatesAndReturnsCategory()
    {
        // Arrange
        var request = new CreateCategoryRequest
        {
            Name = "New Category",
            Description = "A new category",
            CollectionId = 1
        };

        // Act
        var response = await Client.PostAsJsonAsync("/api/categories", request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await DeserializeResponseAsync<Category>(response);
        Assert.NotNull(created);
        Assert.Equal("New Category", created.Name);
        Assert.Equal("A new category", created.Description);
        Assert.Equal(DefaultTenantId, created.TenantId);
        Assert.False(created.IsSystem);
    }

    [Fact]
    public async Task CreateCategory_WithParent_SetsParentRelationship()
    {
        // Arrange
        var parentCategory = await CreateTestCategory("Parent Category");

        var request = new CreateCategoryRequest
        {
            Name = "Child Category",
            CollectionId = 1,
            ParentCategoryId = parentCategory.Id
        };

        // Act
        var response = await Client.PostAsJsonAsync("/api/categories", request);

        // Assert
        response.EnsureSuccessStatusCode();
        var created = await DeserializeResponseAsync<Category>(response);
        Assert.NotNull(created);
        Assert.Equal(parentCategory.Id, created.ParentCategoryId);
    }

    [Fact]
    public async Task CreateCategory_WithVisibility_SetsVisibility()
    {
        // Arrange - First need a public collection to allow setting Public visibility
        await Factory.SeedDatabaseAsync(context =>
        {
            var collection = context.Collections.First(c => c.Id == 1);
            collection.Visibility = Visibility.Public;
        });

        var request = new CreateCategoryRequest
        {
            Name = "Public Category",
            CollectionId = 1,
            Visibility = Visibility.Public
        };

        // Act
        var response = await PostJsonAsync("/api/categories", request);

        // Assert
        response.EnsureSuccessStatusCode();
        var created = await DeserializeResponseAsync<Category>(response);
        Assert.NotNull(created);
        Assert.Equal(Visibility.Public, created.Visibility);
    }

    [Fact]
    public async Task CreateCategory_WithPublicVisibility_WhenCollectionPrivate_ReturnsBadRequest()
    {
        // Arrange - Ensure collection is private (may have been changed by other tests)
        await Factory.SeedDatabaseAsync(context =>
        {
            var collection = context.Collections.First(c => c.Id == 1);
            collection.Visibility = Visibility.Private;
        });

        var request = new CreateCategoryRequest
        {
            Name = "Invalid Public Category",
            CollectionId = 1,
            Visibility = Visibility.Public
        };

        // Act
        var response = await PostJsonAsync("/api/categories", request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task CreateCategory_WithPublicVisibility_WhenParentPrivate_ReturnsBadRequest()
    {
        // Arrange - Create a public collection and a private parent category
        await Factory.SeedDatabaseAsync(context =>
        {
            var collection = context.Collections.First(c => c.Id == 1);
            collection.Visibility = Visibility.Public;
        });

        var parentRequest = new CreateCategoryRequest
        {
            Name = "Private Parent",
            CollectionId = 1,
            Visibility = Visibility.Private
        };
        var parentResponse = await PostJsonAsync("/api/categories", parentRequest);
        var parentCategory = await DeserializeResponseAsync<Category>(parentResponse);

        var request = new CreateCategoryRequest
        {
            Name = "Invalid Public Child",
            CollectionId = 1,
            ParentCategoryId = parentCategory!.Id,
            Visibility = Visibility.Public
        };

        // Act
        var response = await PostJsonAsync("/api/categories", request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    #endregion

    #region PUT /api/categories/{id}

    [Fact]
    public async Task UpdateCategory_ValidRequest_UpdatesCategory()
    {
        // Arrange
        var category = await CreateTestCategory("Original Name");
        var request = new UpdateCategoryRequest
        {
            Name = "Updated Name",
            Description = "Updated description"
        };

        // Act
        var response = await Client.PutAsJsonAsync($"/api/categories/{category.Id}", request);

        // Assert
        response.EnsureSuccessStatusCode();
        var updated = await DeserializeResponseAsync<Category>(response);
        Assert.NotNull(updated);
        Assert.Equal("Updated Name", updated.Name);
        Assert.Equal("Updated description", updated.Description);
    }

    [Fact]
    public async Task UpdateCategory_ChangeParent_MovesCategory()
    {
        // Arrange
        var category = await CreateTestCategory("Movable Category");
        var newParent = await CreateTestCategory("New Parent");

        var request = new UpdateCategoryRequest
        {
            Name = "Movable Category",
            ParentCategoryId = newParent.Id
        };

        // Act
        var response = await Client.PutAsJsonAsync($"/api/categories/{category.Id}", request);

        // Assert
        response.EnsureSuccessStatusCode();
        var updated = await DeserializeResponseAsync<Category>(response);
        Assert.Equal(newParent.Id, updated!.ParentCategoryId);
    }

    [Fact]
    public async Task UpdateCategory_NonExistentId_ReturnsNotFound()
    {
        // Arrange
        var request = new UpdateCategoryRequest { Name = "Updated" };

        // Act
        var response = await Client.PutAsJsonAsync("/api/categories/99999", request);

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task UpdateCategory_SystemCategory_ReturnsForbidden()
    {
        // Arrange - Category ID 1 is the system "Unassigned Items" category
        var request = new UpdateCategoryRequest { Name = "Renamed System Category" };

        // Act
        var response = await Client.PutAsJsonAsync("/api/categories/1", request);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    #endregion

    #region DELETE /api/categories/{id}

    [Fact]
    public async Task DeleteCategory_ExistingId_DeletesCategory()
    {
        // Arrange
        var category = await CreateTestCategory("Category to Delete");

        // Act
        var response = await Client.DeleteAsync($"/api/categories/{category.Id}");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        // Verify deleted
        var getResponse = await Client.GetAsync($"/api/categories/{category.Id}");
        Assert.Equal(HttpStatusCode.NotFound, getResponse.StatusCode);
    }

    [Fact]
    public async Task DeleteCategory_SystemCategory_ReturnsForbidden()
    {
        // Act - Try to delete system category
        var response = await Client.DeleteAsync("/api/categories/1");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task DeleteCategory_NonExistentId_ReturnsNotFound()
    {
        // Act
        var response = await Client.DeleteAsync("/api/categories/99999");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task DeleteCategory_WithItems_MovesItemsToUnassigned()
    {
        // Arrange - Create category with an item
        var category = await CreateTestCategory("Category with Items");
        var itemRequest = new CreateItemRequest
        {
            Name = "Item to Reassign",
            CollectionId = 1,
            CategoryId = category.Id
        };
        await Client.PostAsJsonAsync("/api/items", itemRequest);

        // Act
        var response = await Client.DeleteAsync($"/api/categories/{category.Id}");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        // Verify item still exists (should be moved to unassigned)
        var itemsResponse = await Client.GetAsync("/api/items?collectionId=1");
        var items = await DeserializeResponseAsync<List<Item>>(itemsResponse);
        Assert.Contains(items!, i => i.Name == "Item to Reassign");
    }

    #endregion

    #region Template Association

    [Fact]
    public async Task GetCategoryTemplates_ReturnsTemplateIds()
    {
        // Arrange
        var category = await CreateTestCategory("Template Category");

        // Act
        var response = await Client.GetAsync($"/api/categories/{category.Id}/templates");

        // Assert
        response.EnsureSuccessStatusCode();
        var templateIds = await DeserializeResponseAsync<List<int>>(response);
        Assert.NotNull(templateIds);
        // Initially no templates associated
    }

    [Fact]
    public async Task CreateCategory_WithTemplates_AssociatesTemplates()
    {
        // Arrange - Create a category with templates via the request
        var request = new CreateCategoryRequest
        {
            Name = "Category With Templates",
            CollectionId = 1,
            ItemTemplateIds = new List<int> { 1, 2 } // General Item and Book templates
        };

        // Act
        var response = await Client.PostAsJsonAsync("/api/categories", request);

        // Assert
        response.EnsureSuccessStatusCode();
        var created = await DeserializeResponseAsync<Category>(response);
        Assert.NotNull(created);

        // Verify templates were associated by checking the templates endpoint
        var getResponse = await Client.GetAsync($"/api/categories/{created.Id}/templates");
        var templateIds = await DeserializeResponseAsync<List<int>>(getResponse);
        Assert.Contains(1, templateIds!);
        Assert.Contains(2, templateIds!);
    }

    #endregion

    #region Helper Methods

    private async Task<Category> CreateTestCategory(
        string name,
        int? parentCategoryId = null)
    {
        var request = new CreateCategoryRequest
        {
            Name = name,
            CollectionId = 1,
            ParentCategoryId = parentCategoryId
        };

        var response = await Client.PostAsJsonAsync("/api/categories", request);
        response.EnsureSuccessStatusCode();
        return (await DeserializeResponseAsync<Category>(response))!;
    }

    #endregion
}
