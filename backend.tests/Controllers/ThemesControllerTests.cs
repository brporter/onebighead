using backend.Controllers;
using backend.Data;
using backend.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Security.Claims;

namespace backend.Tests.Controllers;

[Trait("Category", "Unit")]
public class ThemesControllerTests
{
    private readonly Mock<IThemeRepository> _mockThemeRepository;
    private readonly ThemesController _controller;

    public ThemesControllerTests()
    {
        _mockThemeRepository = new Mock<IThemeRepository>();
        _controller = new ThemesController(_mockThemeRepository.Object);

        var claims = new List<Claim>
        {
            new("tenant_id", "1"),
            new("sub", "1"),
            new(ClaimTypes.NameIdentifier, "1"),
            new(ClaimTypes.Email, "test@example.com")
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var claimsPrincipal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = claimsPrincipal }
        };
    }

    #region GetThemes Tests

    [Fact]
    public async Task GetThemes_ReturnsOkResult_WithThemesOrderedBySortOrder()
    {
        // Arrange
        var themes = new List<CollectionTheme>
        {
            new()
            {
                Id = 2,
                Name = "Video Games",
                Description = "For video game collections",
                IconName = "gamepad",
                SortOrder = 2,
                ThemeTemplates = new List<CollectionThemeTemplate>(),
                ThemeCategories = new List<CollectionThemeCategory>()
            },
            new()
            {
                Id = 1,
                Name = "Books",
                Description = "For book collections",
                IconName = "book",
                SortOrder = 1,
                ThemeTemplates = new List<CollectionThemeTemplate>(),
                ThemeCategories = new List<CollectionThemeCategory>()
            }
        };

        _mockThemeRepository.Setup(repo => repo.GetAllAsync())
            .ReturnsAsync(themes);

        // Act
        var result = await _controller.GetThemes();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedThemes = Assert.IsAssignableFrom<IEnumerable<backend.DTOs.CollectionThemeDto>>(okResult.Value);
        Assert.Equal(2, returnedThemes.Count());
    }

    [Fact]
    public async Task GetThemes_ReturnsEmptyList_WhenNoThemesExist()
    {
        // Arrange
        _mockThemeRepository.Setup(repo => repo.GetAllAsync())
            .ReturnsAsync(new List<CollectionTheme>());

        // Act
        var result = await _controller.GetThemes();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedThemes = Assert.IsAssignableFrom<IEnumerable<backend.DTOs.CollectionThemeDto>>(okResult.Value);
        Assert.Empty(returnedThemes);
    }

    [Fact]
    public async Task GetThemes_IncludesTemplatesAndCategories()
    {
        // Arrange
        var itemTemplate = new ItemTemplate
        {
            Id = 1,
            Name = "Book Template",
            Description = "Template for books",
            Properties = new List<ItemTemplateProperty>
            {
                new() { Id = 1, Name = "Author", Category = "Details", SortOrder = 1 }
            }
        };

        var themes = new List<CollectionTheme>
        {
            new()
            {
                Id = 1,
                Name = "Books",
                Description = "For book collections",
                IconName = "book",
                SortOrder = 1,
                ThemeTemplates = new List<CollectionThemeTemplate>
                {
                    new() { ThemeId = 1, ItemTemplateId = 1, SortOrder = 1, ItemTemplate = itemTemplate }
                },
                ThemeCategories = new List<CollectionThemeCategory>
                {
                    new() { ThemeId = 1, Name = "Fiction", Description = "Fiction books", SortOrder = 1 },
                    new() { ThemeId = 1, Name = "Non-Fiction", Description = "Non-fiction books", SortOrder = 2 }
                }
            }
        };

        _mockThemeRepository.Setup(repo => repo.GetAllAsync())
            .ReturnsAsync(themes);

        // Act
        var result = await _controller.GetThemes();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedThemes = Assert.IsAssignableFrom<IEnumerable<backend.DTOs.CollectionThemeDto>>(okResult.Value).ToList();
        Assert.Single(returnedThemes);
        
        var theme = returnedThemes[0];
        Assert.Single(theme.Templates);
        Assert.Equal("Book Template", theme.Templates[0].Name);
        Assert.Equal(2, theme.Categories.Count);
    }

    #endregion

    #region GetTheme Tests

    [Fact]
    public async Task GetTheme_ReturnsOkResult_WhenThemeExists()
    {
        // Arrange
        var theme = new CollectionTheme
        {
            Id = 1,
            Name = "Books",
            Description = "For book collections",
            IconName = "book",
            SortOrder = 1,
            ThemeTemplates = new List<CollectionThemeTemplate>(),
            ThemeCategories = new List<CollectionThemeCategory>()
        };

        _mockThemeRepository.Setup(repo => repo.GetByIdAsync(1))
            .ReturnsAsync(theme);

        // Act
        var result = await _controller.GetTheme(1);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedTheme = Assert.IsType<backend.DTOs.CollectionThemeDto>(okResult.Value);
        Assert.Equal(1, returnedTheme.ThemeId);
        Assert.Equal("Books", returnedTheme.Name);
    }

    [Fact]
    public async Task GetTheme_ReturnsNotFound_WhenThemeDoesNotExist()
    {
        // Arrange
        _mockThemeRepository.Setup(repo => repo.GetByIdAsync(999))
            .ReturnsAsync((CollectionTheme?)null);

        // Act
        var result = await _controller.GetTheme(999);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    #endregion
}
