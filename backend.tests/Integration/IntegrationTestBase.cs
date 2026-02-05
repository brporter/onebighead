using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using Microsoft.Extensions.DependencyInjection;

namespace OneBigHead.Server.Tests.Integration;

/// <summary>
/// Base class for integration tests providing common functionality.
/// Each test class gets its own isolated database via IClassFixture.
/// </summary>
[Trait("Category", "Integration")]
public abstract class IntegrationTestBase : IClassFixture<CustomWebApplicationFactory>, IAsyncLifetime
{
    protected readonly CustomWebApplicationFactory Factory;
    protected HttpClient Client = null!;
    protected readonly JsonSerializerOptions JsonOptions;

    // Default test entities - these are seeded once per test class
    protected const int DefaultWorkspaceId = 1;
    protected const int DefaultUserId = 1;
    protected const string DefaultEmail = "test@example.com";
    protected const int DefaultCollectionId = 1;
    protected const int DefaultNormalUserId = 2;
    protected const string DefaultNormalUserEmail = "normal@example.com";

    protected IntegrationTestBase(CustomWebApplicationFactory factory)
    {
        Factory = factory;

        JsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters = { new JsonStringEnumConverter() }
        };
    }

    public virtual async Task InitializeAsync()
    {
        // Seed default data - idempotent check inside SeedDefaultDataSync
        SeedDefaultDataSync();

        // Allow derived classes to add additional seeding
        await SeedAdditionalDataAsync();

        // Create a fresh client for each test
        Client = Factory.CreateAuthenticatedClient(DefaultWorkspaceId, DefaultUserId, DefaultEmail);
    }

    public virtual Task DisposeAsync()
    {
        Client?.Dispose();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Seeds the database with default test data synchronously.
    /// This is called once per test class.
    /// </summary>
    private void SeedDefaultDataSync()
    {
        using var scope = Factory.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        // Check if already seeded (in case of race condition)
        if (context.Workspaces.Any(t => t.Id == DefaultWorkspaceId))
        {
            return;
        }

        // Create default workspace
        context.Workspaces.Add(new Workspace
        {
            Id = DefaultWorkspaceId,
            Name = "Test Workspace"
        });

        // Create default user (WorkspaceAdmin)
        context.Users.Add(new User
        {
            Id = DefaultUserId,
            ActiveWorkspaceId = DefaultWorkspaceId,
            Email = DefaultEmail,
            IdentityProvider = IdentityProvider.Microsoft,
            ProviderSubjectId = "test-user-1"
        });

        // Create WorkspaceUser membership
        context.WorkspaceUsers.Add(new WorkspaceUser
        {
            UserId = DefaultUserId,
            WorkspaceId = DefaultWorkspaceId,
            WorkspaceRole = WorkspaceRole.WorkspaceAdmin
        });

        // Create default normal user (for authorization tests)
        context.Users.Add(new User
        {
            Id = DefaultNormalUserId,
            ActiveWorkspaceId = DefaultWorkspaceId,
            Email = DefaultNormalUserEmail,
            IdentityProvider = IdentityProvider.Microsoft,
            ProviderSubjectId = "test-normal-user-2"
        });

        // Create WorkspaceUser membership for normal user
        context.WorkspaceUsers.Add(new WorkspaceUser
        {
            UserId = DefaultNormalUserId,
            WorkspaceId = DefaultWorkspaceId,
            WorkspaceRole = WorkspaceRole.Normal
        });

        // Create default collection
        context.Collections.Add(new Collection
        {
            Id = DefaultCollectionId,
            WorkspaceId = DefaultWorkspaceId,
            Name = "Test Collection",
            Slug = "test-collection",
            Description = "A test collection",
            Visibility = Visibility.Private
        });

        // Create default system category (unassigned items)
        context.Categories.Add(new Category
        {
            Id = 1,
            WorkspaceId = DefaultWorkspaceId,
            CollectionId = DefaultCollectionId,
            Name = "Unassigned Items",
            Description = "Items not assigned to a category",
            IsSystem = true
        });

        // Seed system item templates
        context.ItemTemplates.AddRange(
            new ItemTemplate
            {
                Id = 1,
                WorkspaceId = null, // System template
                Name = "General Item",
                Description = "A general purpose item template",
                Properties = new List<ItemTemplateProperty>
                {
                    new() { Name = "Condition", Category = "General", SortOrder = 1 }
                }
            },
            new ItemTemplate
            {
                Id = 2,
                WorkspaceId = null, // System template
                Name = "Book",
                Description = "A book item template",
                Properties = new List<ItemTemplateProperty>
                {
                    new() { Name = "Author", Category = "Details", SortOrder = 1 },
                    new() { Name = "ISBN", Category = "Details", SortOrder = 2 },
                    new() { Name = "Publisher", Category = "Details", SortOrder = 3 }
                }
            }
        );

        context.SaveChanges();
    }

    /// <summary>
    /// Override this method in derived classes to add additional seed data.
    /// Called after default seeding, for each test.
    /// </summary>
    protected virtual Task SeedAdditionalDataAsync()
    {
        return Task.CompletedTask;
    }

    /// <summary>
    /// Creates an authenticated client for a different workspace/user.
    /// </summary>
    protected HttpClient CreateClientForWorkspace(int workspaceId, int userId, string email = "other@example.com", string workspaceRole = "WorkspaceAdmin")
    {
        return Factory.CreateAuthenticatedClient(workspaceId, userId, email, workspaceRole);
    }

    /// <summary>
    /// Creates an unauthenticated client for testing anonymous access.
    /// </summary>
    protected HttpClient CreateAnonymousClient()
    {
        return Factory.CreateUnauthenticatedClient();
    }

    /// <summary>
    /// Creates an authenticated client with Normal (non-admin) role for the default workspace.
    /// </summary>
    protected HttpClient CreateNormalUserClient(int userId = DefaultNormalUserId, string email = DefaultNormalUserEmail)
    {
        return Factory.CreateAuthenticatedClient(DefaultWorkspaceId, userId, email, "Normal");
    }

    /// <summary>
    /// Creates an authenticated client with WorkspaceAdmin role for the default workspace.
    /// </summary>
    protected HttpClient CreateAdminUserClient(int userId = DefaultUserId, string email = DefaultEmail)
    {
        return Factory.CreateAuthenticatedClient(DefaultWorkspaceId, userId, email, "WorkspaceAdmin");
    }

    /// <summary>
    /// Helper to deserialize HTTP response content.
    /// </summary>
    protected async Task<T?> DeserializeResponseAsync<T>(HttpResponseMessage response)
    {
        var content = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<T>(content, JsonOptions);
    }

    /// <summary>
    /// Helper to POST JSON with correct serialization options (enums as strings).
    /// </summary>
    protected Task<HttpResponseMessage> PostJsonAsync<T>(string url, T content)
    {
        return Client.PostAsJsonAsync(url, content, JsonOptions);
    }

    /// <summary>
    /// Helper to POST JSON with a specific client and correct serialization options.
    /// </summary>
    protected Task<HttpResponseMessage> PostJsonAsync<T>(HttpClient client, string url, T content)
    {
        return client.PostAsJsonAsync(url, content, JsonOptions);
    }

    /// <summary>
    /// Helper to PUT JSON with correct serialization options (enums as strings).
    /// </summary>
    protected Task<HttpResponseMessage> PutJsonAsync<T>(string url, T content)
    {
        return Client.PutAsJsonAsync(url, content, JsonOptions);
    }

    /// <summary>
    /// Helper to PUT JSON with a specific client and correct serialization options.
    /// </summary>
    protected Task<HttpResponseMessage> PutJsonAsync<T>(HttpClient client, string url, T content)
    {
        return client.PutAsJsonAsync(url, content, JsonOptions);
    }

    /// <summary>
    /// Gets a fresh database context for direct database operations.
    /// </summary>
    protected AppDbContext GetDbContext()
    {
        return Factory.GetDbContext();
    }

    /// <summary>
    /// Gets the next available ID for a given entity type to avoid conflicts.
    /// </summary>
    protected int GetNextId<T>() where T : class
    {
        using var scope = Factory.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        // Use reflection to find the max ID
        var dbSet = context.Set<T>();
        var maxId = 0;

        try
        {
            // Try to get max ID using dynamic approach
            foreach (var entity in dbSet)
            {
                var idProp = entity.GetType().GetProperty("Id");
                if (idProp != null)
                {
                    var id = (int?)idProp.GetValue(entity) ?? 0;
                    if (id > maxId) maxId = id;
                }
            }
        }
        catch
        {
            // Fallback to a high number to avoid conflicts
            maxId = 1000;
        }

        return maxId + 1;
    }
}
