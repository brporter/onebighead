using System.Net;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class CollectionsControllerTests : IntegrationTestBase
{
    public CollectionsControllerTests(CustomWebApplicationFactory factory)
        : base(factory)
    {
    }

    #region GET /api/collections

    [Fact]
    public async Task GetCollections_ReturnsAllWorkspaceCollections()
    {
        // Act
        var response = await Client.GetAsync("/api/collections");

        // Assert
        response.EnsureSuccessStatusCode();
        var collections = await DeserializeResponseAsync<List<Collection>>(response);
        Assert.NotNull(collections);
        // Should have at least one collection
        Assert.NotEmpty(collections);
        // All collections should belong to the default workspace
        Assert.All(collections, c => Assert.Equal(DefaultWorkspaceId, c.WorkspaceId));
    }

    [Fact]
    public async Task GetCollections_Unauthenticated_ReturnsUnauthorized()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();

        // Act
        var response = await anonClient.GetAsync("/api/collections");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GetCollections_DifferentWorkspace_ReturnsOnlyOwnCollections()
    {
        // Arrange - Create a second workspace with their own collection (use high IDs to avoid conflicts)
        const int workspace2Id = 1002;
        const int user2Id = 1002;
        const int collection2Id = 1002;

        await Factory.SeedDatabaseAsync(context =>
        {
            // Skip if already seeded
            if (context.Workspaces.Any(t => t.Id == workspace2Id))
                return;

            context.Workspaces.Add(new Workspace { Id = workspace2Id, Name = "Workspace 1002" });
            context.Users.Add(new User
            {
                Id = user2Id,
                ActiveWorkspaceId = workspace2Id,
                Email = "user1002@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "test-user-1002"
            });
            context.WorkspaceUsers.Add(new WorkspaceUser
            {
                UserId = user2Id,
                WorkspaceId = workspace2Id,
                WorkspaceRole = WorkspaceRole.WorkspaceAdmin
            });
            context.Collections.Add(new Collection
            {
                Id = collection2Id,
                WorkspaceId = workspace2Id,
                Name = "Workspace 1002 Collection",
                Slug = "workspace-1002-collection"
            });
        });

        using var workspace2Client = CreateClientForWorkspace(workspace2Id, user2Id, "user1002@example.com");

        // Act
        var response = await workspace2Client.GetAsync("/api/collections");

        // Assert
        response.EnsureSuccessStatusCode();
        var collections = await DeserializeResponseAsync<List<Collection>>(response);
        Assert.NotNull(collections);
        Assert.Single(collections);
        Assert.Equal("Workspace 1002 Collection", collections[0].Name);
    }

    #endregion

    #region GET /api/collections/{id}

    [Fact]
    public async Task GetCollection_ExistingId_ReturnsCollection()
    {
        // Arrange - Create a collection we can reliably test
        var createRequest = new CreateCollectionRequest { Name = "Get Test Collection" };
        var createResponse = await PostJsonAsync("/api/collections", createRequest);
        createResponse.EnsureSuccessStatusCode();
        var created = await DeserializeResponseAsync<Collection>(createResponse);

        // Act
        var response = await Client.GetAsync($"/api/collections/{created!.Id}");

        // Assert
        response.EnsureSuccessStatusCode();
        var collection = await DeserializeResponseAsync<Collection>(response);
        Assert.NotNull(collection);
        Assert.Equal("Get Test Collection", collection.Name);
        Assert.Equal(created.Id, collection.Id);
    }

    [Fact]
    public async Task GetCollection_NonExistentId_ReturnsNotFound()
    {
        // Act
        var response = await Client.GetAsync("/api/collections/999");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GetCollection_OtherWorkspaceCollection_ReturnsNotFound()
    {
        // Arrange - use high IDs to avoid conflicts
        const int otherWorkspaceId = 3003;
        const int otherCollectionId = 3003;

        await Factory.SeedDatabaseAsync(context =>
        {
            // Skip if already seeded (check both workspace and collection)
            if (context.Collections.Any(c => c.Id == otherCollectionId))
                return;

            if (!context.Workspaces.Any(t => t.Id == otherWorkspaceId))
            {
                context.Workspaces.Add(new Workspace { Id = otherWorkspaceId, Name = "Workspace 3003" });
            }
            context.Collections.Add(new Collection
            {
                Id = otherCollectionId,
                WorkspaceId = otherWorkspaceId,
                Name = "Other Workspace Collection",
                Slug = "other-workspace-3003"
            });
        });

        // Act - Try to access other workspace's collection from workspace 1
        var response = await Client.GetAsync($"/api/collections/{otherCollectionId}");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    #endregion

    #region GET /api/collections/by-slug/{slug}

    [Fact]
    public async Task GetCollectionBySlug_ExistingSlug_ReturnsCollection()
    {
        // Arrange - Create a collection with a known slug
        var createRequest = new CreateCollectionRequest { Name = "Slug Test Collection" };
        var createResponse = await PostJsonAsync("/api/collections", createRequest);
        createResponse.EnsureSuccessStatusCode();
        var created = await DeserializeResponseAsync<Collection>(createResponse);

        // Act
        var response = await Client.GetAsync($"/api/collections/by-slug/{created!.Slug}");

        // Assert
        response.EnsureSuccessStatusCode();
        var collection = await DeserializeResponseAsync<Collection>(response);
        Assert.NotNull(collection);
        Assert.Equal("Slug Test Collection", collection.Name);
        Assert.Equal(created.Slug, collection.Slug);
    }

    [Fact]
    public async Task GetCollectionBySlug_NonExistentSlug_ReturnsNotFound()
    {
        // Act
        var response = await Client.GetAsync("/api/collections/by-slug/nonexistent");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    #endregion

    #region POST /api/collections

    [Fact]
    public async Task CreateCollection_ValidRequest_CreatesAndReturnsCollection()
    {
        // Arrange
        var request = new CreateCollectionRequest
        {
            Name = "New Collection",
            Description = "A new test collection"
        };

        // Act
        var response = await PostJsonAsync("/api/collections", request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await DeserializeResponseAsync<Collection>(response);
        Assert.NotNull(created);
        Assert.Equal("New Collection", created.Name);
        Assert.Equal("new-collection", created.Slug);
        Assert.False(created.EffectiveIsPublic);
        Assert.Equal(Visibility.Private, created.Visibility);
        Assert.Equal(DefaultWorkspaceId, created.WorkspaceId);

        // Verify persisted in database
        using var context = GetDbContext();
        var dbCollection = await context.Collections.FindAsync(created.Id);
        Assert.NotNull(dbCollection);
        Assert.Equal("New Collection", dbCollection.Name);
    }

    [Fact]
    public async Task CreateCollection_DuplicateSlug_GeneratesUniqueSlug()
    {
        // Arrange - First create a collection with a known slug
        var firstRequest = new CreateCollectionRequest
        {
            Name = "Duplicate Slug Base",
            Description = "First collection"
        };
        var firstResponse = await PostJsonAsync("/api/collections", firstRequest);
        firstResponse.EnsureSuccessStatusCode();
        var first = await DeserializeResponseAsync<Collection>(firstResponse);

        // Now create another collection with the same name - should get a unique slug
        var secondRequest = new CreateCollectionRequest
        {
            Name = "Duplicate Slug Base", // Same name, should generate unique slug
            Description = "Second collection with same name"
        };

        // Act
        var response = await PostJsonAsync("/api/collections", secondRequest);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await DeserializeResponseAsync<Collection>(response);
        Assert.NotNull(created);
        Assert.NotEqual(first!.Slug, created.Slug); // Should be different
        Assert.StartsWith("duplicate-slug-base", created.Slug);
    }

    [Fact]
    public async Task CreateCollection_CreatesUnassignedItemsCategory()
    {
        // Arrange
        var request = new CreateCollectionRequest { Name = "Collection With Category" };

        // Act
        var response = await PostJsonAsync("/api/collections", request);

        // Assert
        response.EnsureSuccessStatusCode();
        var created = await DeserializeResponseAsync<Collection>(response);

        // Verify the unassigned items category was created
        using var context = GetDbContext();
        var categories = context.Categories
            .Where(c => c.CollectionId == created!.Id && c.IsSystem)
            .ToList();
        Assert.Single(categories);
        Assert.Equal("Unassigned Items", categories[0].Name);
    }

    #endregion

    #region PUT /api/collections/{id}

    [Fact]
    public async Task UpdateCollection_ValidRequest_UpdatesCollection()
    {
        // Arrange
        var request = new UpdateCollectionRequest
        {
            Name = "Updated Collection",
            Description = "Updated description"
        };

        // Act
        var response = await PutJsonAsync("/api/collections/1", request);

        // Assert
        response.EnsureSuccessStatusCode();
        var updated = await DeserializeResponseAsync<Collection>(response);
        Assert.NotNull(updated);
        Assert.Equal("Updated Collection", updated.Name);
        Assert.Equal("Updated description", updated.Description);
    }

    [Fact]
    public async Task UpdateCollection_NonExistentId_ReturnsNotFound()
    {
        // Arrange
        var request = new UpdateCollectionRequest { Name = "Updated" };

        // Act
        var response = await PutJsonAsync("/api/collections/999", request);

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    #endregion

    #region DELETE /api/collections/{id}

    [Fact]
    public async Task DeleteCollection_LastCollection_ReturnsBadRequest()
    {
        // Arrange - Create a fresh workspace with only one collection
        const int isolatedWorkspaceId = 2000;
        const int isolatedUserId = 2000;
        const int isolatedCollectionId = 2000;

        await Factory.SeedDatabaseAsync(context =>
        {
            if (context.Workspaces.Any(t => t.Id == isolatedWorkspaceId))
                return;

            context.Workspaces.Add(new Workspace { Id = isolatedWorkspaceId, Name = "Isolated Workspace" });
            context.Users.Add(new User
            {
                Id = isolatedUserId,
                ActiveWorkspaceId = isolatedWorkspaceId,
                Email = "isolated@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "isolated-user"
            });
            context.WorkspaceUsers.Add(new WorkspaceUser
            {
                UserId = isolatedUserId,
                WorkspaceId = isolatedWorkspaceId,
                WorkspaceRole = WorkspaceRole.WorkspaceAdmin
            });
            context.Collections.Add(new Collection
            {
                Id = isolatedCollectionId,
                WorkspaceId = isolatedWorkspaceId,
                Name = "Only Collection",
                Slug = "only-collection"
            });
        });

        using var isolatedClient = CreateClientForWorkspace(isolatedWorkspaceId, isolatedUserId, "isolated@example.com");

        // Act - Try to delete the only collection for this workspace
        var response = await isolatedClient.DeleteAsync($"/api/collections/{isolatedCollectionId}");

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task DeleteCollection_NotLastCollection_DeletesCollection()
    {
        // Arrange - Create a second collection
        var createRequest = new CreateCollectionRequest { Name = "Second Collection" };
        var createResponse = await PostJsonAsync("/api/collections", createRequest);
        var secondCollection = await DeserializeResponseAsync<Collection>(createResponse);

        // Act - Delete the second collection
        var response = await Client.DeleteAsync($"/api/collections/{secondCollection!.Id}");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        // Verify deleted
        var getResponse = await Client.GetAsync($"/api/collections/{secondCollection.Id}");
        Assert.Equal(HttpStatusCode.NotFound, getResponse.StatusCode);
    }

    [Fact]
    public async Task DeleteCollection_OtherWorkspaceCollection_ReturnsNotFound()
    {
        // Arrange - use very high IDs to avoid conflicts with auto-generated IDs
        const int otherWorkspaceId = 99990004;
        const int otherCollectionId = 99990004;
        const int extraCollectionId = 99990005;

        await Factory.SeedDatabaseAsync(context =>
        {
            // Add a second collection to workspace 1 so the "last collection" check passes
            // (the controller checks count before ownership, so we need > 1 collection)
            if (!context.Collections.Any(c => c.Id == extraCollectionId))
            {
                context.Collections.Add(new Collection
                {
                    Id = extraCollectionId,
                    WorkspaceId = DefaultWorkspaceId,
                    Name = "Extra Collection for Delete Test",
                    Slug = "extra-collection-delete-test"
                });
            }

            // Create the other workspace if not exists
            if (!context.Workspaces.Any(t => t.Id == otherWorkspaceId))
            {
                context.Workspaces.Add(new Workspace { Id = otherWorkspaceId, Name = "Other Workspace for Delete Test" });
            }

            // Create collection in the OTHER workspace (not workspace 1)
            if (!context.Collections.Any(c => c.Id == otherCollectionId))
            {
                context.Collections.Add(new Collection
                {
                    Id = otherCollectionId,
                    WorkspaceId = otherWorkspaceId,
                    Name = "Other Workspace Collection",
                    Slug = "other-workspace-collection-delete-test"
                });
            }
        });

        // Act - Try to delete another workspace's collection (should fail)
        var response = await Client.DeleteAsync($"/api/collections/{otherCollectionId}");

        // Assert - should get NotFound because collection belongs to different workspace
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    #endregion

    #region Templates Association

    [Fact]
    public async Task GetCollectionTemplates_ReturnsTemplates()
    {
        // Act - Get templates for collection 1 (seeded by base class)
        var response = await Client.GetAsync($"/api/collections/{DefaultCollectionId}/templates");

        // Assert
        response.EnsureSuccessStatusCode();
        var templates = await DeserializeResponseAsync<List<ItemTemplateResponse>>(response);
        Assert.NotNull(templates);
        // Initially no templates are associated with the collection
    }

    [Fact]
    public async Task AssociateTemplate_ValidRequest_AssociatesTemplate()
    {
        // Arrange - Create a new collection for this test to avoid conflicts
        var createRequest = new CreateCollectionRequest { Name = "Template Test Collection" };
        var createResponse = await PostJsonAsync("/api/collections", createRequest);
        createResponse.EnsureSuccessStatusCode();
        var collection = await DeserializeResponseAsync<Collection>(createResponse);

        // Act - Associate the General Item template (id=1) with the new collection
        var response = await Client.PostAsync($"/api/collections/{collection!.Id}/templates/1", null);

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        // Verify association
        var getResponse = await Client.GetAsync($"/api/collections/{collection.Id}/templates");
        var templates = await DeserializeResponseAsync<List<ItemTemplateResponse>>(getResponse);
        Assert.NotNull(templates);
        Assert.Contains(templates, t => t.Name == "General Item");
    }

    [Fact]
    public async Task DisassociateTemplate_ExistingAssociation_RemovesAssociation()
    {
        // Arrange - Create a new collection and associate a template
        var createRequest = new CreateCollectionRequest { Name = "Disassociate Test Collection" };
        var createResponse = await PostJsonAsync("/api/collections", createRequest);
        createResponse.EnsureSuccessStatusCode();
        var collection = await DeserializeResponseAsync<Collection>(createResponse);

        // Associate the template first
        var associateResponse = await Client.PostAsync($"/api/collections/{collection!.Id}/templates/1", null);
        Assert.Equal(HttpStatusCode.NoContent, associateResponse.StatusCode);

        // Act - Disassociate the template
        var response = await Client.DeleteAsync($"/api/collections/{collection.Id}/templates/1");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        // Verify no longer associated
        var getResponse = await Client.GetAsync($"/api/collections/{collection.Id}/templates");
        var templates = await DeserializeResponseAsync<List<ItemTemplateResponse>>(getResponse);
        Assert.DoesNotContain(templates!, t => t.Name == "General Item");
    }

    #endregion
}
