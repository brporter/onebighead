using System.Net;
using System.Net.Http.Json;
using backend.DTOs;
using backend.Models;

namespace backend.Tests.Integration;

[Trait("Category", "Integration")]
public class ThemesControllerTests : IntegrationTestBase
{
    public ThemesControllerTests(CustomWebApplicationFactory factory)
        : base(factory)
    {
    }

    protected override async Task SeedAdditionalDataAsync()
    {
        // Seed collection themes (idempotent)
        await Factory.SeedDatabaseAsync(context =>
        {
            // Skip if themes already exist
            if (context.CollectionThemes.Any(t => t.Id == 1))
            {
                return;
            }

            var theme1 = new CollectionTheme
            {
                Id = 1,
                Name = "Books",
                Description = "For book collections",
                IconName = "book",
                ThemeTemplates = new List<CollectionThemeTemplate>
                {
                    new() { ItemTemplateId = 2, SortOrder = 1 }  // Book template
                },
                ThemeCategories = new List<CollectionThemeCategory>
                {
                    new() { Name = "Fiction", Description = "Fiction books", SortOrder = 1 },
                    new() { Name = "Non-Fiction", Description = "Non-fiction books", SortOrder = 2 }
                }
            };

            var theme2 = new CollectionTheme
            {
                Id = 2,
                Name = "General",
                Description = "For general collections",
                IconName = "box"
            };

            context.CollectionThemes.AddRange(theme1, theme2);
        });
    }

    #region GET /api/themes

    [Fact]
    public async Task GetThemes_Authenticated_ReturnsThemes()
    {
        // Act
        var response = await Client.GetAsync("/api/themes");

        // Assert
        response.EnsureSuccessStatusCode();
        var themes = await DeserializeResponseAsync<List<CollectionThemeDto>>(response);
        Assert.NotNull(themes);
        Assert.Contains(themes, t => t.Name == "Books");
        Assert.Contains(themes, t => t.Name == "General");
    }

    [Fact]
    public async Task GetThemes_Unauthenticated_ReturnsUnauthorized()
    {
        // Arrange - Themes require authentication
        using var anonClient = CreateAnonymousClient();

        // Act
        var response = await anonClient.GetAsync("/api/themes");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    #endregion

    #region GET /api/themes/{id}

    [Fact]
    public async Task GetTheme_ExistingId_ReturnsThemeWithDetails()
    {
        // Act
        var response = await Client.GetAsync("/api/themes/1");

        // Assert
        response.EnsureSuccessStatusCode();
        var theme = await DeserializeResponseAsync<CollectionThemeDto>(response);
        Assert.NotNull(theme);
        Assert.Equal("Books", theme.Name);
        Assert.Equal("book", theme.IconName);
        Assert.NotEmpty(theme.Templates);
        Assert.NotEmpty(theme.Categories);
    }

    [Fact]
    public async Task GetTheme_NonExistentId_ReturnsNotFound()
    {
        // Act
        var response = await Client.GetAsync("/api/themes/99999");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GetTheme_IncludesTemplatesAndCategories()
    {
        // Act
        var response = await Client.GetAsync("/api/themes/1");

        // Assert
        var theme = await DeserializeResponseAsync<CollectionThemeDto>(response);
        Assert.NotNull(theme);

        // Verify templates
        Assert.Single(theme.Templates);
        Assert.Equal(2, theme.Templates.First().ItemTemplateId); // Book template

        // Verify categories
        Assert.Equal(2, theme.Categories.Count);
        Assert.Contains(theme.Categories, c => c.Name == "Fiction");
        Assert.Contains(theme.Categories, c => c.Name == "Non-Fiction");
    }

    #endregion
}
