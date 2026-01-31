using System.Net;
using System.Net.Http.Json;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

/// <summary>
/// Tests that verify TenantAdmin authorization policies are properly enforced.
/// Normal users should receive 403 Forbidden on admin-only endpoints.
/// </summary>
[Trait("Category", "Integration")]
public class AuthorizationTests : IntegrationTestBase
{
    public AuthorizationTests(CustomWebApplicationFactory factory)
        : base(factory)
    {
    }

    #region Collections Controller - Admin-Only Endpoints

    [Fact]
    public async Task CreateCollection_AsNormalUser_ReturnsForbidden()
    {
        // Arrange
        using var normalClient = CreateNormalUserClient();
        var request = new CreateCollectionRequest
        {
            Name = "Should Fail Collection",
            Description = "This should not be created"
        };

        // Act
        var response = await PostJsonAsync(normalClient, "/api/collections", request);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task CreateCollection_AsAdmin_Succeeds()
    {
        // Arrange
        var request = new CreateCollectionRequest
        {
            Name = "Admin Created Collection",
            Description = "This should succeed"
        };

        // Act
        var response = await PostJsonAsync("/api/collections", request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task SetupCollection_AsNormalUser_ReturnsForbidden()
    {
        // Arrange
        using var normalClient = CreateNormalUserClient();
        var request = new SetupCollectionRequest
        {
            Name = "Should Fail Setup",
            ThemeId = 1
        };

        // Act
        var response = await PostJsonAsync(normalClient, "/api/collections/setup", request);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task DeleteCollection_AsNormalUser_ReturnsForbidden()
    {
        // Arrange - First create a second collection as admin (so we can attempt deletion)
        var createRequest = new CreateCollectionRequest { Name = "Deletable Collection" };
        var createResponse = await PostJsonAsync("/api/collections", createRequest);
        var collection = await DeserializeResponseAsync<Collection>(createResponse);

        using var normalClient = CreateNormalUserClient();

        // Act
        var response = await normalClient.DeleteAsync($"/api/collections/{collection!.Id}");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task DeleteCollection_AsAdmin_Succeeds()
    {
        // Arrange - Create a second collection
        var createRequest = new CreateCollectionRequest { Name = "Admin Deletable Collection" };
        var createResponse = await PostJsonAsync("/api/collections", createRequest);
        var collection = await DeserializeResponseAsync<Collection>(createResponse);

        // Act
        var response = await Client.DeleteAsync($"/api/collections/{collection!.Id}");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task GetCollections_AsNormalUser_Succeeds()
    {
        // Arrange - Normal users CAN read collections
        using var normalClient = CreateNormalUserClient();

        // Act
        var response = await normalClient.GetAsync("/api/collections");

        // Assert
        response.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task UpdateCollection_AsNormalUser_Succeeds()
    {
        // Arrange - Normal users CAN update collections (not create/delete)
        using var normalClient = CreateNormalUserClient();
        var request = new UpdateCollectionRequest
        {
            Name = "Updated by Normal User",
            Description = "Updated description"
        };

        // Act
        var response = await PutJsonAsync(normalClient, $"/api/collections/{DefaultCollectionId}", request);

        // Assert
        response.EnsureSuccessStatusCode();
    }

    #endregion

    #region ItemTemplates Controller - Admin-Only Endpoints

    [Fact]
    public async Task CreateTemplate_AsNormalUser_ReturnsForbidden()
    {
        // Arrange
        using var normalClient = CreateNormalUserClient();
        var request = new CreateItemTemplateRequest
        {
            Name = "Should Fail Template",
            Description = "This should not be created"
        };

        // Act
        var response = await PostJsonAsync(normalClient, "/api/itemtemplates", request);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task CreateTemplate_AsAdmin_Succeeds()
    {
        // Arrange
        var request = new CreateItemTemplateRequest
        {
            Name = "Admin Created Template",
            Description = "This should succeed"
        };

        // Act
        var response = await PostJsonAsync("/api/itemtemplates", request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task UpdateTemplate_AsNormalUser_ReturnsForbidden()
    {
        // Arrange - First create a template as admin
        var createRequest = new CreateItemTemplateRequest { Name = "Updateable Template" };
        var createResponse = await PostJsonAsync("/api/itemtemplates", createRequest);
        var template = await DeserializeResponseAsync<ItemTemplateResponse>(createResponse);

        using var normalClient = CreateNormalUserClient();
        var updateRequest = new UpdateItemTemplateRequest
        {
            Name = "Should Fail Update",
            Description = "This should not work"
        };

        // Act
        var response = await PutJsonAsync(normalClient, $"/api/itemtemplates/{template!.ItemTemplateId}", updateRequest);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task DeleteTemplate_AsNormalUser_ReturnsForbidden()
    {
        // Arrange - First create a template as admin
        var createRequest = new CreateItemTemplateRequest { Name = "Deleteable Template" };
        var createResponse = await PostJsonAsync("/api/itemtemplates", createRequest);
        var template = await DeserializeResponseAsync<ItemTemplateResponse>(createResponse);

        using var normalClient = CreateNormalUserClient();

        // Act
        var response = await normalClient.DeleteAsync($"/api/itemtemplates/{template!.ItemTemplateId}");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task GetTemplates_AsNormalUser_Succeeds()
    {
        // Arrange - Normal users CAN read templates
        using var normalClient = CreateNormalUserClient();

        // Act
        var response = await normalClient.GetAsync("/api/itemtemplates");

        // Assert
        response.EnsureSuccessStatusCode();
    }

    #endregion

    #region Export Controller - Admin-Only Endpoints

    [Fact]
    public async Task ExportData_AsNormalUser_ReturnsForbidden()
    {
        // Arrange
        using var normalClient = CreateNormalUserClient();

        // Act
        var response = await normalClient.GetAsync("/api/export");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task ExportData_AsAdmin_Succeeds()
    {
        // Act
        var response = await Client.GetAsync("/api/export");

        // Assert
        response.EnsureSuccessStatusCode();
    }

    #endregion

    #region Items Controller - Normal User Capabilities

    [Fact]
    public async Task CreateItem_AsNormalUser_Succeeds()
    {
        // Arrange - Normal users CAN create items
        using var normalClient = CreateNormalUserClient();
        var request = new CreateItemRequest
        {
            CollectionId = DefaultCollectionId,
            Name = "Normal User Item",
            Summary = "Created by normal user",
            Description = "This should work"
        };

        // Act
        var response = await PostJsonAsync(normalClient, "/api/items", request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task GetItems_AsNormalUser_Succeeds()
    {
        // Arrange
        using var normalClient = CreateNormalUserClient();

        // Act
        var response = await normalClient.GetAsync($"/api/items?collectionId={DefaultCollectionId}");

        // Assert
        response.EnsureSuccessStatusCode();
    }

    #endregion

    #region Categories Controller - Normal User Capabilities

    [Fact]
    public async Task CreateCategory_AsNormalUser_Succeeds()
    {
        // Arrange - Normal users CAN create categories
        using var normalClient = CreateNormalUserClient();
        var request = new CreateCategoryRequest
        {
            CollectionId = DefaultCollectionId,
            Name = "Normal User Category",
            Description = "Created by normal user"
        };

        // Act
        var response = await PostJsonAsync(normalClient, "/api/categories", request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task GetCategories_AsNormalUser_Succeeds()
    {
        // Arrange
        using var normalClient = CreateNormalUserClient();

        // Act
        var response = await normalClient.GetAsync($"/api/categories?collectionId={DefaultCollectionId}");

        // Assert
        response.EnsureSuccessStatusCode();
    }

    #endregion

    #region Users Controller - Admin-Only Access

    [Fact]
    public async Task GetUsers_AsNormalUser_ReturnsForbidden()
    {
        // Arrange
        using var normalClient = CreateNormalUserClient();

        // Act
        var response = await normalClient.GetAsync("/api/users");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task InviteUser_AsNormalUser_ReturnsForbidden()
    {
        // Arrange
        using var normalClient = CreateNormalUserClient();
        var request = new InviteUserRequest
        {
            Email = "unauthorized@example.com",
            Role = TenantRole.Normal
        };

        // Act
        var response = await PostJsonAsync(normalClient, "/api/users", request);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task UpdateUserRole_AsNormalUser_ReturnsForbidden()
    {
        // Arrange
        using var normalClient = CreateNormalUserClient();
        var request = new UpdateUserRoleRequest { Role = TenantRole.TenantAdmin };

        // Act
        var response = await PutJsonAsync(normalClient, "/api/users/1/role", request);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task RemoveUser_AsNormalUser_ReturnsForbidden()
    {
        // Arrange
        using var normalClient = CreateNormalUserClient();

        // Act
        var response = await normalClient.DeleteAsync("/api/users/1");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    #endregion
}
