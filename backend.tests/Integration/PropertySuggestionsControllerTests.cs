using System.Net;
using System.Net.Http.Json;
using backend.DTOs;
using backend.Models;

namespace backend.Tests.Integration;

[Trait("Category", "Integration")]
public class PropertySuggestionsControllerTests : IntegrationTestBase
{
    public PropertySuggestionsControllerTests(CustomWebApplicationFactory factory)
        : base(factory)
    {
    }

    #region GET /api/collections/{id}/property-suggestions

    [Fact]
    public async Task GetSuggestions_ValidCollection_ReturnsSuggestions()
    {
        // Act
        var response = await Client.GetAsync("/api/collections/1/property-suggestions");

        // Assert
        response.EnsureSuccessStatusCode();
        var suggestions = await DeserializeResponseAsync<PropertySuggestionsResponse>(response);
        Assert.NotNull(suggestions);
        Assert.NotNull(suggestions.Categories);
        Assert.NotNull(suggestions.Names);
    }

    [Fact]
    public async Task GetSuggestions_NonExistentCollection_ReturnsNotFound()
    {
        // Act
        var response = await Client.GetAsync("/api/collections/99999/property-suggestions");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GetSuggestions_OtherTenantCollection_ReturnsNotFound()
    {
        // Arrange
        await Factory.SeedDatabaseAsync(context =>
        {
            var tenant = new Tenant { Id = 50, Name = "Other Tenant" };
            context.Tenants.Add(tenant);

            var collection = new Collection
            {
                Id = 50,
                TenantId = 50,
                Name = "Other Collection",
                Slug = "other"
            };
            context.Collections.Add(collection);
        });

        // Act
        var response = await Client.GetAsync("/api/collections/50/property-suggestions");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GetSuggestions_Unauthenticated_ReturnsUnauthorized()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();

        // Act
        var response = await anonClient.GetAsync("/api/collections/1/property-suggestions");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    #endregion

    #region POST /api/collections/{id}/property-suggestions/sync

    [Fact]
    public async Task SyncSuggestions_ValidCollection_ReturnsSuggestions()
    {
        // Act
        var response = await Client.PostAsync("/api/collections/1/property-suggestions/sync", null);

        // Assert
        response.EnsureSuccessStatusCode();
        var suggestions = await DeserializeResponseAsync<PropertySuggestionsResponse>(response);
        Assert.NotNull(suggestions);
    }

    [Fact]
    public async Task SyncSuggestions_NonExistentCollection_ReturnsNotFound()
    {
        // Act
        var response = await Client.PostAsync("/api/collections/99999/property-suggestions/sync", null);

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    #endregion
}
