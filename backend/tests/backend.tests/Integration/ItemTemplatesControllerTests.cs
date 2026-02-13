using System.Net;
using System.Net.Http.Json;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class ItemTemplatesControllerTests : IntegrationTestBase
{
    public ItemTemplatesControllerTests(CustomWebApplicationFactory factory)
        : base(factory)
    {
    }

    #region GET /api/itemtemplates

    [Fact]
    public async Task GetTemplates_ReturnsSystemAndWorkspaceTemplates()
    {
        // Act
        var response = await Client.GetAsync("/api/itemtemplates");

        // Assert
        response.EnsureSuccessStatusCode();
        var templates = await DeserializeResponseAsync<List<ItemTemplateResponse>>(response);
        Assert.NotNull(templates);
        // Should include system templates (General Item, Book)
        Assert.True(templates.Count >= 2);
        Assert.Contains(templates, t => t.Name == "General Item");
        Assert.Contains(templates, t => t.Name == "Book");
    }

    [Fact]
    public async Task GetTemplates_WithSystemFilter_ReturnsOnlySystemTemplates()
    {
        // Arrange - First create a workspace template
        var createRequest = new CreateItemTemplateRequest
        {
            Name = "Workspace Template",
            Description = "A workspace template"
        };
        await Client.PostAsJsonAsync("/api/itemtemplates", createRequest);

        // Act
        var response = await Client.GetAsync("/api/itemtemplates?filter=system");

        // Assert
        response.EnsureSuccessStatusCode();
        var templates = await DeserializeResponseAsync<List<ItemTemplateResponse>>(response);
        Assert.NotNull(templates);
        Assert.All(templates, t => Assert.True(t.IsSystem));
    }

    [Fact]
    public async Task GetTemplates_WithWorkspaceFilter_ReturnsOnlyWorkspaceTemplates()
    {
        // Arrange - First create a workspace template
        var createRequest = new CreateItemTemplateRequest
        {
            Name = "My Template",
            Description = "My custom template"
        };
        await Client.PostAsJsonAsync("/api/itemtemplates", createRequest);

        // Act
        var response = await Client.GetAsync("/api/itemtemplates?filter=workspace");

        // Assert
        response.EnsureSuccessStatusCode();
        var templates = await DeserializeResponseAsync<List<ItemTemplateResponse>>(response);
        Assert.NotNull(templates);
        Assert.All(templates, t => Assert.False(t.IsSystem));
    }

    [Fact]
    public async Task GetTemplates_Unauthenticated_ReturnsUnauthorized()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();

        // Act
        var response = await anonClient.GetAsync("/api/itemtemplates");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    #endregion

    #region GET /api/itemtemplates/{id}

    [Fact]
    public async Task GetTemplate_SystemTemplate_ReturnsTemplate()
    {
        // Act - Get the Book template (id=2)
        var response = await Client.GetAsync("/api/itemtemplates/2");

        // Assert
        response.EnsureSuccessStatusCode();
        var template = await DeserializeResponseAsync<ItemTemplateResponse>(response);
        Assert.NotNull(template);
        Assert.Equal("Book", template.Name);
        Assert.True(template.IsSystem);
        Assert.NotEmpty(template.Properties);
        Assert.Contains(template.Properties, p => p.Name == "Author");
    }

    [Fact]
    public async Task GetTemplate_NonExistentId_ReturnsNotFound()
    {
        // Act
        var response = await Client.GetAsync("/api/itemtemplates/99999");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    #endregion

    #region POST /api/itemtemplates

    [Fact]
    public async Task CreateTemplate_ValidRequest_CreatesAndReturnsTemplate()
    {
        // Arrange
        var request = new CreateItemTemplateRequest
        {
            Name = "Custom Template",
            Description = "A custom template",
            Properties = new List<ItemTemplatePropertyDto>
            {
                new() { Name = "Custom Field", Category = "General" },
                new() { Name = "Notes", Category = "Details" }
            }
        };

        // Act
        var response = await Client.PostAsJsonAsync("/api/itemtemplates", request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await DeserializeResponseAsync<ItemTemplateResponse>(response);
        Assert.NotNull(created);
        Assert.Equal("Custom Template", created.Name);
        Assert.False(created.IsSystem);
        Assert.Equal(2, created.Properties.Count);
    }

    [Fact]
    public async Task CreateTemplate_WithoutProperties_CreatesEmptyTemplate()
    {
        // Arrange
        var request = new CreateItemTemplateRequest
        {
            Name = "Empty Template",
            Description = "A template with no properties"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/api/itemtemplates", request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await DeserializeResponseAsync<ItemTemplateResponse>(response);
        Assert.NotNull(created);
        Assert.Empty(created.Properties);
    }

    #endregion

    #region PUT /api/itemtemplates/{id}

    [Fact]
    public async Task UpdateTemplate_UserTemplate_UpdatesTemplate()
    {
        // Arrange - Create a user template first
        var createRequest = new CreateItemTemplateRequest
        {
            Name = "Original Template",
            Description = "Original description"
        };
        var createResponse = await Client.PostAsJsonAsync("/api/itemtemplates", createRequest);
        var created = await DeserializeResponseAsync<ItemTemplateResponse>(createResponse);

        var updateRequest = new UpdateItemTemplateRequest
        {
            Name = "Updated Template",
            Description = "Updated description",
            Properties = new List<ItemTemplatePropertyDto>
            {
                new() { Name = "New Property", Category = "New Category" }
            }
        };

        // Act
        var response = await Client.PutAsJsonAsync($"/api/itemtemplates/{created!.ItemTemplateId}", updateRequest);

        // Assert
        response.EnsureSuccessStatusCode();
        var updated = await DeserializeResponseAsync<ItemTemplateResponse>(response);
        Assert.NotNull(updated);
        Assert.Equal("Updated Template", updated.Name);
        Assert.Equal("Updated description", updated.Description);
        Assert.Single(updated.Properties);
    }

    [Fact]
    public async Task UpdateTemplate_SystemTemplate_CreatesWorkspaceCopy()
    {
        // Arrange
        var updateRequest = new UpdateItemTemplateRequest
        {
            Name = "My Custom Book Template",
            Description = "A customized book template"
        };

        // Act - Try to update system template (id=2, Book)
        var response = await Client.PutAsJsonAsync("/api/itemtemplates/2", updateRequest);

        // Assert - Should succeed by creating a copy, not BadRequest
        response.EnsureSuccessStatusCode();
        var updated = await DeserializeResponseAsync<ItemTemplateResponse>(response);
        Assert.NotNull(updated);
        Assert.Equal("My Custom Book Template", updated.Name);
        Assert.False(updated.IsSystem); // Now a workspace copy
        Assert.NotEqual(2, updated.ItemTemplateId); // Different ID
    }

    [Fact]
    public async Task UpdateTemplate_OtherWorkspaceTemplate_ReturnsNotFound()
    {
        // Arrange - Create template in another workspace
        await Factory.SeedDatabaseAsync(context =>
        {
            var workspace = new Workspace { Id = 30, Name = "Other" };
            context.Workspaces.Add(workspace);

            var template = new ItemTemplate
            {
                Id = 3000,
                WorkspaceId = 30,
                Name = "Other Workspace Template"
            };
            context.ItemTemplates.Add(template);
        });

        var updateRequest = new UpdateItemTemplateRequest { Name = "Hacked" };

        // Act
        var response = await Client.PutAsJsonAsync("/api/itemtemplates/3000", updateRequest);

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    #endregion

    #region DELETE /api/itemtemplates/{id}

    [Fact]
    public async Task DeleteTemplate_UserTemplate_DeletesTemplate()
    {
        // Arrange
        var createRequest = new CreateItemTemplateRequest { Name = "Deletable Template" };
        var createResponse = await Client.PostAsJsonAsync("/api/itemtemplates", createRequest);
        var created = await DeserializeResponseAsync<ItemTemplateResponse>(createResponse);

        // Act
        var response = await Client.DeleteAsync($"/api/itemtemplates/{created!.ItemTemplateId}");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        // Verify deleted
        var getResponse = await Client.GetAsync($"/api/itemtemplates/{created.ItemTemplateId}");
        Assert.Equal(HttpStatusCode.NotFound, getResponse.StatusCode);
    }

    [Fact]
    public async Task DeleteTemplate_SystemTemplate_ReturnsNotFound()
    {
        // Act - Try to delete system template (repository returns false for system templates)
        var response = await Client.DeleteAsync("/api/itemtemplates/1");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    #endregion

    #region Multi-Tenancy Tests

    [Fact]
    public async Task GetTemplates_DifferentWorkspace_DoesNotSeeOtherWorkspaceTemplates()
    {
        // Arrange - Create a template for workspace 1
        var createRequest = new CreateItemTemplateRequest
        {
            Name = "Workspace 1 Only Template"
        };
        await Client.PostAsJsonAsync("/api/itemtemplates", createRequest);

        // Create workspace 2
        await Factory.SeedDatabaseAsync(context =>
        {
            var workspace2 = new Workspace { Id = 40, Name = "Workspace 2" };
            context.Workspaces.Add(workspace2);

            var user2 = new User
            {
                Id = 40,
                ActiveWorkspaceId = 40,
                Email = "user2@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "user2"
            };
            context.Users.Add(user2);
            context.WorkspaceUsers.Add(new WorkspaceUser
            {
                UserId = 40,
                WorkspaceId = 40,
                WorkspaceRole = WorkspaceRole.WorkspaceAdmin
            });
        });

        using var workspace2Client = CreateClientForWorkspace(40, 40, "user2@example.com");

        // Act
        var response = await workspace2Client.GetAsync("/api/itemtemplates");

        // Assert
        response.EnsureSuccessStatusCode();
        var templates = await DeserializeResponseAsync<List<ItemTemplateResponse>>(response);
        Assert.DoesNotContain(templates!, t => t.Name == "Workspace 1 Only Template");
    }

    #endregion
}
