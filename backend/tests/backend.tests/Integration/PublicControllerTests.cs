using System.Net;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using Microsoft.Extensions.DependencyInjection;
using OneBigHead.Server.Data;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class PublicControllerTests : IntegrationTestBase
{
    // Test workspace IDs (high to avoid conflicts with default seeded data)
    private const int PublicWorkspaceId = 100;
    private const int DisabledWorkspaceId = 101;
    private const string PublicWorkspaceSlug = "test-public";
    private const string DisabledWorkspaceSlug = "test-disabled";

    // Collection IDs
    private const int PublicCollectionId = 100;
    private const int PrivateCollectionId = 101;

    // Category IDs
    private const int PublicCategoryId = 100;
    private const int PrivateCategoryId = 101;
    private const int SystemCategoryId = 102;

    // Item IDs
    private const int PublicItemId = 100;
    private const int PrivateItemId = 101;
    private const int PublicItemInPrivateCategoryId = 102;

    public PublicControllerTests(CustomWebApplicationFactory factory)
        : base(factory)
    {
    }

    protected override Task SeedAdditionalDataAsync()
    {
        using var scope = Factory.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        // Skip if already seeded
        if (context.Workspaces.Any(w => w.Id == PublicWorkspaceId))
            return Task.CompletedTask;

        // Workspace with public access enabled
        context.Workspaces.Add(new Workspace
        {
            Id = PublicWorkspaceId,
            Name = "Public Test Workspace",
            Slug = PublicWorkspaceSlug,
            IsPublicAccessEnabled = true
        });

        // Workspace with public access disabled
        context.Workspaces.Add(new Workspace
        {
            Id = DisabledWorkspaceId,
            Name = "Disabled Test Workspace",
            Slug = DisabledWorkspaceSlug,
            IsPublicAccessEnabled = false
        });

        // Public collection
        context.Collections.Add(new Collection
        {
            Id = PublicCollectionId,
            WorkspaceId = PublicWorkspaceId,
            Name = "Public Collection",
            Slug = "public-collection",
            Description = "A publicly visible collection",
            Visibility = Visibility.Public
        });

        // Private collection
        context.Collections.Add(new Collection
        {
            Id = PrivateCollectionId,
            WorkspaceId = PublicWorkspaceId,
            Name = "Private Collection",
            Slug = "private-collection",
            Description = "A private collection",
            Visibility = Visibility.Private
        });

        // System category (Unassigned Items) for the public collection
        context.Categories.Add(new Category
        {
            Id = SystemCategoryId,
            WorkspaceId = PublicWorkspaceId,
            CollectionId = PublicCollectionId,
            Name = "Unassigned Items",
            Description = "Items not assigned to a category",
            IsSystem = true,
            Visibility = Visibility.Private
        });

        // Public category in the public collection
        context.Categories.Add(new Category
        {
            Id = PublicCategoryId,
            WorkspaceId = PublicWorkspaceId,
            CollectionId = PublicCollectionId,
            Name = "Public Category",
            Description = "A publicly visible category",
            Visibility = Visibility.Public
        });

        // Private category in the public collection
        context.Categories.Add(new Category
        {
            Id = PrivateCategoryId,
            WorkspaceId = PublicWorkspaceId,
            CollectionId = PublicCollectionId,
            Name = "Private Category",
            Description = "A private category",
            Visibility = Visibility.Private
        });

        // Public item in the public category
        context.Items.Add(new Item
        {
            Id = PublicItemId,
            WorkspaceId = PublicWorkspaceId,
            CollectionId = PublicCollectionId,
            CategoryId = PublicCategoryId,
            Name = "Public Item",
            Summary = "A publicly visible item",
            Description = "Full description of the public item",
            Visibility = Visibility.Public,
            Properties = new List<ItemProperty>
            {
                new("General", "Condition", "Mint")
            },
            Images = new List<ItemImage>
            {
                new("https://example.com/image1.jpg", "Test image")
            }
        });

        // Private item in the public category
        context.Items.Add(new Item
        {
            Id = PrivateItemId,
            WorkspaceId = PublicWorkspaceId,
            CollectionId = PublicCollectionId,
            CategoryId = PublicCategoryId,
            Name = "Private Item",
            Summary = "A private item",
            Description = "Full description of the private item",
            Visibility = Visibility.Private
        });

        // Public item in the private category (should not appear in public results)
        context.Items.Add(new Item
        {
            Id = PublicItemInPrivateCategoryId,
            WorkspaceId = PublicWorkspaceId,
            CollectionId = PublicCollectionId,
            CategoryId = PrivateCategoryId,
            Name = "Item In Private Category",
            Summary = "An item in a private category",
            Description = "This item is in a private category so it should not be public",
            Visibility = Visibility.Public
        });

        context.SaveChanges();
        return Task.CompletedTask;
    }

    #region GET /api/public/{slug} - GetWorkspace

    [Fact]
    public async Task GetWorkspace_ValidSlug_ReturnsWorkspace()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();

        // Act
        var response = await anonClient.GetAsync($"/api/public/{PublicWorkspaceSlug}");

        // Assert
        response.EnsureSuccessStatusCode();
        var workspace = await DeserializeResponseAsync<PublicWorkspaceDto>(response);
        Assert.NotNull(workspace);
        Assert.Equal("Public Test Workspace", workspace.Name);
        Assert.Equal(PublicWorkspaceSlug, workspace.Slug);
    }

    [Fact]
    public async Task GetWorkspace_InvalidSlug_Returns404()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();

        // Act
        var response = await anonClient.GetAsync("/api/public/nonexistent-slug");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GetWorkspace_DisabledPublicAccess_Returns404()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();

        // Act
        var response = await anonClient.GetAsync($"/api/public/{DisabledWorkspaceSlug}");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    #endregion

    #region GET /api/public/{slug}/collections - GetCollections

    [Fact]
    public async Task GetCollections_ReturnsOnlyPublicCollections()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();

        // Act
        var response = await anonClient.GetAsync($"/api/public/{PublicWorkspaceSlug}/collections");

        // Assert
        response.EnsureSuccessStatusCode();
        var collections = await DeserializeResponseAsync<List<PublicCollectionDto>>(response);
        Assert.NotNull(collections);
        // Should only contain the public collection, not the private one
        Assert.Single(collections);
        Assert.Equal("Public Collection", collections[0].Name);
        Assert.Equal(PublicCollectionId, collections[0].Id);
        Assert.Equal("public-collection", collections[0].Slug);
    }

    #endregion

    #region GET /api/public/{slug}/collections/{collectionId} - GetCollectionDetail

    [Fact]
    public async Task GetCollection_PublicCollection_ReturnsWithPublicCategories()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();

        // Act
        var response = await anonClient.GetAsync($"/api/public/{PublicWorkspaceSlug}/collections/{PublicCollectionId}");

        // Assert
        response.EnsureSuccessStatusCode();
        var detail = await DeserializeResponseAsync<PublicCollectionDetailDto>(response);
        Assert.NotNull(detail);
        Assert.Equal("Public Collection", detail.Collection.Name);
        Assert.Equal(PublicCollectionId, detail.Collection.Id);

        // Should have the public category and the system category (which inherits from public collection)
        // but NOT the private category
        Assert.DoesNotContain(detail.Categories, c => c.Name == "Private Category");
        Assert.Contains(detail.Categories, c => c.Name == "Public Category");

        // The system category inherits from the public collection, so it should be present
        Assert.Contains(detail.Categories, c => c.Name == "Unassigned Items" && c.IsSystem);
    }

    [Fact]
    public async Task GetCollection_PrivateCollection_Returns404()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();

        // Act
        var response = await anonClient.GetAsync($"/api/public/{PublicWorkspaceSlug}/collections/{PrivateCollectionId}");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    #endregion

    #region GET /api/public/{slug}/collections/{collectionId}/items - GetItems

    [Fact]
    public async Task GetItems_ReturnsOnlyPublicItems()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();

        // Act
        var response = await anonClient.GetAsync($"/api/public/{PublicWorkspaceSlug}/collections/{PublicCollectionId}/items");

        // Assert
        response.EnsureSuccessStatusCode();
        var items = await DeserializeResponseAsync<List<PublicItemSummaryDto>>(response);
        Assert.NotNull(items);

        // Should only contain the public item in the public category
        // The private item should be excluded, and the item in the private category should also be excluded
        Assert.Single(items);
        Assert.Equal("Public Item", items[0].Name);
        Assert.Equal(PublicItemId, items[0].Id);
        Assert.Equal("A publicly visible item", items[0].Summary);
    }

    [Fact]
    public async Task GetItems_WithCategoryFilter_ReturnsFilteredItems()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();

        // Act - Filter to the public category
        var response = await anonClient.GetAsync(
            $"/api/public/{PublicWorkspaceSlug}/collections/{PublicCollectionId}/items?categoryId={PublicCategoryId}");

        // Assert
        response.EnsureSuccessStatusCode();
        var items = await DeserializeResponseAsync<List<PublicItemSummaryDto>>(response);
        Assert.NotNull(items);
        Assert.Single(items);
        Assert.Equal("Public Item", items[0].Name);
        Assert.Equal(PublicCategoryId, items[0].CategoryId);

        // Act - Filter to the private category (should return empty since items in private categories are not public)
        var privateResponse = await anonClient.GetAsync(
            $"/api/public/{PublicWorkspaceSlug}/collections/{PublicCollectionId}/items?categoryId={PrivateCategoryId}");

        // Assert
        privateResponse.EnsureSuccessStatusCode();
        var privateItems = await DeserializeResponseAsync<List<PublicItemSummaryDto>>(privateResponse);
        Assert.NotNull(privateItems);
        Assert.Empty(privateItems);
    }

    #endregion

    #region GET /api/public/{slug}/items/{itemId} - GetItem

    [Fact]
    public async Task GetItem_PublicItem_ReturnsDetails()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();

        // Act
        var response = await anonClient.GetAsync($"/api/public/{PublicWorkspaceSlug}/items/{PublicItemId}");

        // Assert
        response.EnsureSuccessStatusCode();
        var item = await DeserializeResponseAsync<PublicItemDto>(response);
        Assert.NotNull(item);
        Assert.Equal(PublicItemId, item.Id);
        Assert.Equal("Public Item", item.Name);
        Assert.Equal("A publicly visible item", item.Summary);
        Assert.Equal("Full description of the public item", item.Description);
        Assert.Equal(PublicCategoryId, item.CategoryId);
        Assert.Equal("Public Category", item.CategoryName);

        // Verify properties
        Assert.Single(item.Properties);
        Assert.Equal("Condition", item.Properties[0].Name);
        Assert.Equal("Mint", item.Properties[0].Value);
        Assert.Equal("General", item.Properties[0].Category);

        // Verify images
        Assert.Single(item.Images);
        Assert.Equal("https://example.com/image1.jpg", item.Images[0].Url);
        Assert.Equal("Test image", item.Images[0].Alt);
    }

    [Fact]
    public async Task GetItem_PrivateItem_Returns404()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();

        // Act
        var response = await anonClient.GetAsync($"/api/public/{PublicWorkspaceSlug}/items/{PrivateItemId}");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    #endregion
}
