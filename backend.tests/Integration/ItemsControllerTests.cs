using System.Net;
using System.Net.Http.Json;
using backend.DTOs;
using backend.Models;

namespace backend.Tests.Integration;

[Trait("Category", "Integration")]
public class ItemsControllerTests : IntegrationTestBase
{
    public ItemsControllerTests(CustomWebApplicationFactory factory)
        : base(factory)
    {
    }

    #region GET /api/items

    [Fact]
    public async Task GetItems_WithCollectionId_ReturnsItems()
    {
        // Arrange - Create items with unique names for this test
        var item1 = await CreateTestItem("GetItems Test Item 1");
        var item2 = await CreateTestItem("GetItems Test Item 2");

        // Act
        var response = await Client.GetAsync("/api/items?collectionId=1");

        // Assert
        response.EnsureSuccessStatusCode();
        var items = await DeserializeResponseAsync<List<Item>>(response);
        Assert.NotNull(items);
        // Verify our created items are present
        Assert.Contains(items, i => i.Id == item1.Id);
        Assert.Contains(items, i => i.Id == item2.Id);
        // All items should belong to collection 1
        Assert.All(items, i => Assert.Equal(DefaultCollectionId, i.CollectionId));
    }

    [Fact]
    public async Task GetItems_WithCategoryFilter_ReturnsFilteredItems()
    {
        // Arrange - Create a category and items in that category
        var categoryRequest = new CreateCategoryRequest
        {
            Name = "Test Category",
            CollectionId = 1
        };
        var categoryResponse = await Client.PostAsJsonAsync("/api/categories", categoryRequest);
        var category = await DeserializeResponseAsync<Category>(categoryResponse);

        await CreateTestItem("Item in Category", categoryId: category!.Id);
        await CreateTestItem("Item without Category");

        // Act
        var response = await Client.GetAsync($"/api/items?collectionId=1&categoryId={category.Id}");

        // Assert
        response.EnsureSuccessStatusCode();
        var items = await DeserializeResponseAsync<List<Item>>(response);
        Assert.NotNull(items);
        Assert.Single(items);
        Assert.Equal("Item in Category", items[0].Name);
    }

    [Fact]
    public async Task GetItems_WithPagination_ReturnsPagedResults()
    {
        // Arrange
        for (int i = 1; i <= 15; i++)
        {
            await CreateTestItem($"Item {i:D2}");
        }

        // Act
        var response = await Client.GetAsync("/api/items?collectionId=1&skip=0&take=5");

        // Assert
        response.EnsureSuccessStatusCode();
        var items = await DeserializeResponseAsync<List<Item>>(response);
        Assert.NotNull(items);
        Assert.Equal(5, items.Count);
    }

    [Fact]
    public async Task GetItems_Unauthenticated_ReturnsUnauthorized()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();

        // Act
        var response = await anonClient.GetAsync("/api/items?collectionId=1");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    #endregion

    #region GET /api/items/{id}

    [Fact]
    public async Task GetItem_ExistingId_ReturnsItem()
    {
        // Arrange
        var item = await CreateTestItem("Get Test Item");

        // Act
        var response = await Client.GetAsync($"/api/items/{item.Id}");

        // Assert
        response.EnsureSuccessStatusCode();
        var returned = await DeserializeResponseAsync<Item>(response);
        Assert.NotNull(returned);
        Assert.Equal("Get Test Item", returned.Name);
    }

    [Fact]
    public async Task GetItem_NonExistentId_ReturnsNotFound()
    {
        // Act
        var response = await Client.GetAsync("/api/items/99999");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GetItem_OtherTenantItem_ReturnsNotFound()
    {
        // Arrange - Create item in another tenant
        await Factory.SeedDatabaseAsync(context =>
        {
            var tenant = new Tenant { Id = 10, Name = "Other Tenant" };
            context.Tenants.Add(tenant);

            var collection = new Collection
            {
                Id = 10,
                TenantId = 10,
                Name = "Other Collection",
                Slug = "other"
            };
            context.Collections.Add(collection);

            var item = new Item
            {
                Id = 1000,
                TenantId = 10,
                CollectionId = 10,
                Name = "Other Tenant Item"
            };
            context.Items.Add(item);
        });

        // Act
        var response = await Client.GetAsync("/api/items/1000");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    #endregion

    #region POST /api/items

    [Fact]
    public async Task CreateItem_ValidRequest_CreatesAndReturnsItem()
    {
        // Arrange
        var request = new CreateItemRequest
        {
            Name = "New Item",
            Summary = "Item summary",
            Description = "Item description",
            CollectionId = 1,
            Properties = new List<ItemProperty>
            {
                new("General", "Color", "Blue")
            }
        };

        // Act
        var response = await Client.PostAsJsonAsync("/api/items", request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await DeserializeResponseAsync<Item>(response);
        Assert.NotNull(created);
        Assert.Equal("New Item", created.Name);
        Assert.Equal("Item summary", created.Summary);
        Assert.Equal(DefaultTenantId, created.TenantId);
        Assert.Single(created.Properties);
        Assert.Equal("Blue", created.Properties[0].Value);
    }

    [Fact]
    public async Task CreateItem_WithUserFlag_PersistsFlag()
    {
        // Arrange
        var request = new CreateItemRequest
        {
            Name = "Item with Flag",
            CollectionId = 1,
            UserFlag = UserFlag.Have
        };

        // Act
        var response = await Client.PostAsJsonAsync("/api/items", request);

        // Assert
        response.EnsureSuccessStatusCode();
        var created = await DeserializeResponseAsync<Item>(response);
        Assert.NotNull(created);
        Assert.Equal(UserFlag.Have, created.UserFlag);

        // Verify persisted
        var getResponse = await Client.GetAsync($"/api/items/{created.Id}");
        var fetched = await DeserializeResponseAsync<Item>(getResponse);
        Assert.Equal(UserFlag.Have, fetched!.UserFlag);
    }

    [Fact]
    public async Task CreateItem_WithImages_PersistsImages()
    {
        // Arrange
        var request = new CreateItemRequest
        {
            Name = "Item with Images",
            CollectionId = 1,
            Images = new List<ItemImage>
            {
                new("https://example.com/image1.jpg", "Image 1"),
                new("https://example.com/image2.jpg", "Image 2")
            }
        };

        // Act
        var response = await Client.PostAsJsonAsync("/api/items", request);

        // Assert
        response.EnsureSuccessStatusCode();
        var created = await DeserializeResponseAsync<Item>(response);
        Assert.NotNull(created);
        Assert.Equal(2, created.Images.Count);
    }

    [Fact]
    public async Task CreateItem_WithCategoryId_AssignsToCategory()
    {
        // Arrange
        var categoryRequest = new CreateCategoryRequest
        {
            Name = "Item Category",
            CollectionId = 1
        };
        var categoryResponse = await Client.PostAsJsonAsync("/api/categories", categoryRequest);
        var category = await DeserializeResponseAsync<Category>(categoryResponse);

        var request = new CreateItemRequest
        {
            Name = "Categorized Item",
            CollectionId = 1,
            CategoryId = category!.Id
        };

        // Act
        var response = await Client.PostAsJsonAsync("/api/items", request);

        // Assert
        response.EnsureSuccessStatusCode();
        var created = await DeserializeResponseAsync<Item>(response);
        Assert.NotNull(created);
        Assert.Equal(category.Id, created.CategoryId);
    }

    #endregion

    #region PUT /api/items/{id}

    [Fact]
    public async Task UpdateItem_ValidRequest_UpdatesItem()
    {
        // Arrange
        var item = await CreateTestItem("Original Name");
        var request = new UpdateItemRequest
        {
            Name = "Updated Name",
            Summary = "Updated summary",
            CollectionId = 1
        };

        // Act
        var response = await Client.PutAsJsonAsync($"/api/items/{item.Id}", request);

        // Assert
        response.EnsureSuccessStatusCode();
        var updated = await DeserializeResponseAsync<Item>(response);
        Assert.NotNull(updated);
        Assert.Equal("Updated Name", updated.Name);
        Assert.Equal("Updated summary", updated.Summary);
    }

    [Fact]
    public async Task UpdateItem_ChangeUserFlag_UpdatesFlag()
    {
        // Arrange
        var item = await CreateTestItem("Flag Item", userFlag: UserFlag.None);
        var request = new UpdateItemRequest
        {
            Name = "Flag Item",
            CollectionId = 1,
            UserFlag = UserFlag.Want
        };

        // Act
        var response = await Client.PutAsJsonAsync($"/api/items/{item.Id}", request);

        // Assert
        response.EnsureSuccessStatusCode();
        var updated = await DeserializeResponseAsync<Item>(response);
        Assert.Equal(UserFlag.Want, updated!.UserFlag);
    }

    [Fact]
    public async Task UpdateItem_NonExistentId_ReturnsNotFound()
    {
        // Arrange
        var request = new UpdateItemRequest
        {
            Name = "Updated",
            CollectionId = 1
        };

        // Act
        var response = await Client.PutAsJsonAsync("/api/items/99999", request);

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task UpdateItem_ChangeCategory_MovesItem()
    {
        // Arrange
        var item = await CreateTestItem("Item to Move");
        var newCategoryRequest = new CreateCategoryRequest
        {
            Name = "New Category",
            CollectionId = 1
        };
        var categoryResponse = await Client.PostAsJsonAsync("/api/categories", newCategoryRequest);
        var newCategory = await DeserializeResponseAsync<Category>(categoryResponse);

        var request = new UpdateItemRequest
        {
            Name = "Item to Move",
            CollectionId = 1,
            CategoryId = newCategory!.Id
        };

        // Act
        var response = await Client.PutAsJsonAsync($"/api/items/{item.Id}", request);

        // Assert
        response.EnsureSuccessStatusCode();
        var updated = await DeserializeResponseAsync<Item>(response);
        Assert.Equal(newCategory.Id, updated!.CategoryId);
    }

    #endregion

    #region DELETE /api/items/{id}

    [Fact]
    public async Task DeleteItem_ExistingId_DeletesItem()
    {
        // Arrange
        var item = await CreateTestItem("Item to Delete");

        // Act
        var response = await Client.DeleteAsync($"/api/items/{item.Id}");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        // Verify deleted
        var getResponse = await Client.GetAsync($"/api/items/{item.Id}");
        Assert.Equal(HttpStatusCode.NotFound, getResponse.StatusCode);
    }

    [Fact]
    public async Task DeleteItem_NonExistentId_ReturnsNotFound()
    {
        // Act
        var response = await Client.DeleteAsync("/api/items/99999");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    #endregion

    #region Full Round-Trip Tests

    [Fact]
    public async Task FullRoundTrip_CreateReadUpdateDelete_Works()
    {
        // Create
        var createRequest = new CreateItemRequest
        {
            Name = "Round Trip Item",
            Summary = "Original summary",
            CollectionId = 1,
            UserFlag = UserFlag.Have,
            Properties = new List<ItemProperty>
            {
                new("General", "Condition", "New")
            }
        };
        var createResponse = await Client.PostAsJsonAsync("/api/items", createRequest);
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
        var created = await DeserializeResponseAsync<Item>(createResponse);

        // Read
        var getResponse = await Client.GetAsync($"/api/items/{created!.Id}");
        Assert.Equal(HttpStatusCode.OK, getResponse.StatusCode);
        var fetched = await DeserializeResponseAsync<Item>(getResponse);
        Assert.Equal("Round Trip Item", fetched!.Name);
        Assert.Equal(UserFlag.Have, fetched.UserFlag);

        // Update
        var updateRequest = new UpdateItemRequest
        {
            Name = "Updated Round Trip Item",
            Summary = "Updated summary",
            CollectionId = 1,
            UserFlag = UserFlag.TradeOrSell,
            Properties = new List<ItemProperty>
            {
                new("General", "Condition", "Like New")
            }
        };
        var updateResponse = await Client.PutAsJsonAsync($"/api/items/{created.Id}", updateRequest);
        Assert.Equal(HttpStatusCode.OK, updateResponse.StatusCode);
        var updated = await DeserializeResponseAsync<Item>(updateResponse);
        Assert.Equal("Updated Round Trip Item", updated!.Name);
        Assert.Equal(UserFlag.TradeOrSell, updated.UserFlag);

        // Delete
        var deleteResponse = await Client.DeleteAsync($"/api/items/{created.Id}");
        Assert.Equal(HttpStatusCode.NoContent, deleteResponse.StatusCode);

        // Verify deleted
        var finalGetResponse = await Client.GetAsync($"/api/items/{created.Id}");
        Assert.Equal(HttpStatusCode.NotFound, finalGetResponse.StatusCode);
    }

    #endregion

    #region Helper Methods

    private async Task<Item> CreateTestItem(
        string name,
        int? categoryId = null,
        UserFlag userFlag = UserFlag.None)
    {
        var request = new CreateItemRequest
        {
            Name = name,
            CollectionId = 1,
            CategoryId = categoryId,
            UserFlag = userFlag
        };

        var response = await Client.PostAsJsonAsync("/api/items", request);
        response.EnsureSuccessStatusCode();
        return (await DeserializeResponseAsync<Item>(response))!;
    }

    #endregion
}
