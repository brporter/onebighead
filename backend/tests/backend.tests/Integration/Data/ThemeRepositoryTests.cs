using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Tests.Integration.Data;

[Trait("Category", "Integration")]
public class ThemeRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly ThemeRepository _repository;

    public ThemeRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _repository = new ThemeRepository(_context);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    #region GetAllAsync Tests

    [Fact]
    public async Task GetAllAsync_ReturnsAllThemesOrderedBySortOrder()
    {
        // Arrange
        var themes = new List<CollectionTheme>
        {
            new() { Id = 1, Name = "Theme C", Description = "Third theme", IconName = "c", SortOrder = 3 },
            new() { Id = 2, Name = "Theme A", Description = "First theme", IconName = "a", SortOrder = 1 },
            new() { Id = 3, Name = "Theme B", Description = "Second theme", IconName = "b", SortOrder = 2 }
        };
        await _context.CollectionThemes.AddRangeAsync(themes);
        await _context.SaveChangesAsync();

        // Act
        var result = (await _repository.GetAllAsync()).ToList();

        // Assert
        Assert.Equal(3, result.Count);
        Assert.Equal("Theme A", result[0].Name);
        Assert.Equal("Theme B", result[1].Name);
        Assert.Equal("Theme C", result[2].Name);
    }

    [Fact]
    public async Task GetAllAsync_ReturnsEmptyList_WhenNoThemesExist()
    {
        // Act
        var result = await _repository.GetAllAsync();

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public async Task GetAllAsync_IncludesThemeTemplatesWithItemTemplates()
    {
        // Arrange
        var itemTemplate = new ItemTemplate
        {
            Id = 1,
            Name = "Book Template",
            Description = "For books",
            Properties = new List<ItemTemplateProperty>
            {
                new() { Id = 1, Name = "Author", Category = "Details", SortOrder = 1 }
            }
        };
        await _context.ItemTemplates.AddAsync(itemTemplate);

        var theme = new CollectionTheme
        {
            Id = 1,
            Name = "Books",
            Description = "For book collections",
            IconName = "book",
            SortOrder = 1
        };
        await _context.CollectionThemes.AddAsync(theme);
        await _context.SaveChangesAsync();

        var themeTemplate = new CollectionThemeTemplate
        {
            ThemeId = 1,
            ItemTemplateId = 1,
            SortOrder = 1
        };
        await _context.CollectionThemeTemplates.AddAsync(themeTemplate);
        await _context.SaveChangesAsync();

        // Act
        var result = (await _repository.GetAllAsync()).ToList();

        // Assert
        Assert.Single(result);
        Assert.Single(result[0].ThemeTemplates);
        Assert.NotNull(result[0].ThemeTemplates.First().ItemTemplate);
        Assert.Equal("Book Template", result[0].ThemeTemplates.First().ItemTemplate!.Name);
    }

    [Fact]
    public async Task GetAllAsync_IncludesThemeCategories()
    {
        // Arrange
        var theme = new CollectionTheme
        {
            Id = 1,
            Name = "Books",
            Description = "For book collections",
            IconName = "book",
            SortOrder = 1
        };
        await _context.CollectionThemes.AddAsync(theme);
        await _context.SaveChangesAsync();

        var categories = new List<CollectionThemeCategory>
        {
            new() { ThemeId = 1, Name = "Fiction", Description = "Fiction books", SortOrder = 1 },
            new() { ThemeId = 1, Name = "Non-Fiction", Description = "Non-fiction books", SortOrder = 2 }
        };
        await _context.CollectionThemeCategories.AddRangeAsync(categories);
        await _context.SaveChangesAsync();

        // Act
        var result = (await _repository.GetAllAsync()).ToList();

        // Assert
        Assert.Single(result);
        Assert.Equal(2, result[0].ThemeCategories.Count);
    }

    #endregion

    #region GetByIdAsync Tests

    [Fact]
    public async Task GetByIdAsync_ReturnsTheme_WhenExists()
    {
        // Arrange
        var theme = new CollectionTheme
        {
            Id = 1,
            Name = "Books",
            Description = "For book collections",
            IconName = "book",
            SortOrder = 1
        };
        await _context.CollectionThemes.AddAsync(theme);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(1);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Books", result.Name);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenNotExists()
    {
        // Act
        var result = await _repository.GetByIdAsync(999);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetByIdAsync_IncludesTemplatesAndCategories()
    {
        // Arrange
        var itemTemplate = new ItemTemplate
        {
            Id = 1,
            Name = "Book Template",
            Description = "For books"
        };
        await _context.ItemTemplates.AddAsync(itemTemplate);

        var theme = new CollectionTheme
        {
            Id = 1,
            Name = "Books",
            Description = "For book collections",
            IconName = "book",
            SortOrder = 1
        };
        await _context.CollectionThemes.AddAsync(theme);
        await _context.SaveChangesAsync();

        await _context.CollectionThemeTemplates.AddAsync(new CollectionThemeTemplate
        {
            ThemeId = 1,
            ItemTemplateId = 1,
            SortOrder = 1
        });
        await _context.CollectionThemeCategories.AddAsync(new CollectionThemeCategory
        {
            ThemeId = 1,
            Name = "Fiction",
            Description = "Fiction books",
            SortOrder = 1
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(1);

        // Assert
        Assert.NotNull(result);
        Assert.Single(result.ThemeTemplates);
        Assert.Single(result.ThemeCategories);
        Assert.NotNull(result.ThemeTemplates.First().ItemTemplate);
    }

    #endregion
}
