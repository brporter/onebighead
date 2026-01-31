using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Tests.Integration.Data;

[Trait("Category", "Integration")]
public class PropertySuggestionRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly PropertySuggestionRepository _repository;
    private const int TestTenantId = 1;
    private const int OtherTenantId = 2;
    private const int TestCollectionId = 1;

    public PropertySuggestionRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _repository = new PropertySuggestionRepository(_context);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    #region GetByCollectionAsync Tests

    [Fact]
    public async Task GetByCollectionAsync_ReturnsSuggestionsForCollection()
    {
        // Arrange
        var suggestions = new List<PropertySuggestion>
        {
            new() { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Type = PropertySuggestionType.Category, Value = "Cat1" },
            new() { Id = 2, TenantId = TestTenantId, CollectionId = TestCollectionId, Type = PropertySuggestionType.Name, Value = "Name1" },
            new() { Id = 3, TenantId = TestTenantId, CollectionId = 999, Type = PropertySuggestionType.Category, Value = "Other" },
            new() { Id = 4, TenantId = OtherTenantId, CollectionId = TestCollectionId, Type = PropertySuggestionType.Category, Value = "OtherTenant" }
        };
        await _context.PropertySuggestions.AddRangeAsync(suggestions);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByCollectionAsync(TestCollectionId, TestTenantId);

        // Assert
        Assert.Equal(2, result.Count());
        Assert.All(result, s => Assert.Equal(TestTenantId, s.TenantId));
        Assert.All(result, s => Assert.Equal(TestCollectionId, s.CollectionId));
    }

    [Fact]
    public async Task GetByCollectionAsync_ReturnsOrderedByTypeAndValue()
    {
        // Arrange
        var suggestions = new List<PropertySuggestion>
        {
            new() { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Type = PropertySuggestionType.Name, Value = "Zebra" },
            new() { Id = 2, TenantId = TestTenantId, CollectionId = TestCollectionId, Type = PropertySuggestionType.Category, Value = "Apple" },
            new() { Id = 3, TenantId = TestTenantId, CollectionId = TestCollectionId, Type = PropertySuggestionType.Category, Value = "Banana" },
            new() { Id = 4, TenantId = TestTenantId, CollectionId = TestCollectionId, Type = PropertySuggestionType.Name, Value = "Alpha" }
        };
        await _context.PropertySuggestions.AddRangeAsync(suggestions);
        await _context.SaveChangesAsync();

        // Act
        var result = (await _repository.GetByCollectionAsync(TestCollectionId, TestTenantId)).ToList();

        // Assert - Categories come first (Type sorted), then alphabetically within type
        Assert.Equal("Apple", result[0].Value);
        Assert.Equal("Banana", result[1].Value);
        Assert.Equal("Alpha", result[2].Value);
        Assert.Equal("Zebra", result[3].Value);
    }

    [Fact]
    public async Task GetByCollectionAsync_ReturnsEmpty_WhenNoSuggestions()
    {
        // Act
        var result = await _repository.GetByCollectionAsync(TestCollectionId, TestTenantId);

        // Assert
        Assert.Empty(result);
    }

    #endregion

    #region GetCategoriesAsync Tests

    [Fact]
    public async Task GetCategoriesAsync_ReturnsOnlyCategoryValues()
    {
        // Arrange
        var suggestions = new List<PropertySuggestion>
        {
            new() { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Type = PropertySuggestionType.Category, Value = "Cat1" },
            new() { Id = 2, TenantId = TestTenantId, CollectionId = TestCollectionId, Type = PropertySuggestionType.Category, Value = "Cat2" },
            new() { Id = 3, TenantId = TestTenantId, CollectionId = TestCollectionId, Type = PropertySuggestionType.Name, Value = "Name1" }
        };
        await _context.PropertySuggestions.AddRangeAsync(suggestions);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetCategoriesAsync(TestCollectionId, TestTenantId);

        // Assert
        Assert.Equal(2, result.Count());
        Assert.Contains("Cat1", result);
        Assert.Contains("Cat2", result);
        Assert.DoesNotContain("Name1", result);
    }

    [Fact]
    public async Task GetCategoriesAsync_ReturnsOrderedByValue()
    {
        // Arrange
        var suggestions = new List<PropertySuggestion>
        {
            new() { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Type = PropertySuggestionType.Category, Value = "Zebra" },
            new() { Id = 2, TenantId = TestTenantId, CollectionId = TestCollectionId, Type = PropertySuggestionType.Category, Value = "Apple" }
        };
        await _context.PropertySuggestions.AddRangeAsync(suggestions);
        await _context.SaveChangesAsync();

        // Act
        var result = (await _repository.GetCategoriesAsync(TestCollectionId, TestTenantId)).ToList();

        // Assert
        Assert.Equal("Apple", result[0]);
        Assert.Equal("Zebra", result[1]);
    }

    #endregion

    #region GetNamesAsync Tests

    [Fact]
    public async Task GetNamesAsync_ReturnsOnlyNameValues()
    {
        // Arrange
        var suggestions = new List<PropertySuggestion>
        {
            new() { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Type = PropertySuggestionType.Category, Value = "Cat1" },
            new() { Id = 2, TenantId = TestTenantId, CollectionId = TestCollectionId, Type = PropertySuggestionType.Name, Value = "Name1" },
            new() { Id = 3, TenantId = TestTenantId, CollectionId = TestCollectionId, Type = PropertySuggestionType.Name, Value = "Name2" }
        };
        await _context.PropertySuggestions.AddRangeAsync(suggestions);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetNamesAsync(TestCollectionId, TestTenantId);

        // Assert
        Assert.Equal(2, result.Count());
        Assert.Contains("Name1", result);
        Assert.Contains("Name2", result);
        Assert.DoesNotContain("Cat1", result);
    }

    #endregion

    #region SyncSuggestionsAsync Tests

    [Fact]
    public async Task SyncSuggestionsAsync_AddsNewSuggestionsFromItems()
    {
        // Arrange
        var item = new Item
        {
            Id = 1,
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Name = "Test Item",
            Properties = new List<ItemProperty>
            {
                new("NewCategory", "NewName", "Value")
            }
        };
        await _context.Items.AddAsync(item);
        await _context.SaveChangesAsync();

        // Act
        await _repository.SyncSuggestionsAsync(TestCollectionId, TestTenantId, Enumerable.Empty<string>(), Enumerable.Empty<string>());

        // Assert
        var suggestions = await _context.PropertySuggestions.ToListAsync();
        Assert.Equal(2, suggestions.Count);
        Assert.Contains(suggestions, s => s.Type == PropertySuggestionType.Category && s.Value == "NewCategory");
        Assert.Contains(suggestions, s => s.Type == PropertySuggestionType.Name && s.Value == "NewName");
    }

    [Fact]
    public async Task SyncSuggestionsAsync_RemovesUnusedSuggestions()
    {
        // Arrange
        var existingSuggestion = new PropertySuggestion
        {
            Id = 1,
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Type = PropertySuggestionType.Category,
            Value = "UnusedCategory"
        };
        await _context.PropertySuggestions.AddAsync(existingSuggestion);
        await _context.SaveChangesAsync();

        // Act - no items, so the suggestion should be removed
        await _repository.SyncSuggestionsAsync(TestCollectionId, TestTenantId, Enumerable.Empty<string>(), Enumerable.Empty<string>());

        // Assert
        Assert.Empty(await _context.PropertySuggestions.ToListAsync());
    }

    [Fact]
    public async Task SyncSuggestionsAsync_KeepsUsedSuggestions()
    {
        // Arrange
        var existingSuggestion = new PropertySuggestion
        {
            Id = 1,
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Type = PropertySuggestionType.Category,
            Value = "UsedCategory"
        };
        var item = new Item
        {
            Id = 1,
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Name = "Test Item",
            Properties = new List<ItemProperty>
            {
                new("UsedCategory", "Name", "Value")
            }
        };
        await _context.PropertySuggestions.AddAsync(existingSuggestion);
        await _context.Items.AddAsync(item);
        await _context.SaveChangesAsync();

        // Act
        await _repository.SyncSuggestionsAsync(TestCollectionId, TestTenantId, Enumerable.Empty<string>(), Enumerable.Empty<string>());

        // Assert
        var suggestions = await _context.PropertySuggestions.Where(s => s.Type == PropertySuggestionType.Category).ToListAsync();
        Assert.Single(suggestions);
        Assert.Equal("UsedCategory", suggestions[0].Value);
    }

    [Fact]
    public async Task SyncSuggestionsAsync_DoesNotDuplicateExisting()
    {
        // Arrange
        var existingSuggestion = new PropertySuggestion
        {
            Id = 1,
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Type = PropertySuggestionType.Category,
            Value = "Category"
        };
        var item = new Item
        {
            Id = 1,
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Name = "Test Item",
            Properties = new List<ItemProperty>
            {
                new("Category", "Name", "Value")
            }
        };
        await _context.PropertySuggestions.AddAsync(existingSuggestion);
        await _context.Items.AddAsync(item);
        await _context.SaveChangesAsync();

        // Act
        await _repository.SyncSuggestionsAsync(TestCollectionId, TestTenantId, Enumerable.Empty<string>(), Enumerable.Empty<string>());

        // Assert
        var categorySuggestions = await _context.PropertySuggestions
            .Where(s => s.Type == PropertySuggestionType.Category)
            .ToListAsync();
        Assert.Single(categorySuggestions);
    }

    [Fact]
    public async Task SyncSuggestionsAsync_HandlesEmptyProperties()
    {
        // Arrange
        var item = new Item
        {
            Id = 1,
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Name = "Test Item",
            Properties = new List<ItemProperty>
            {
                new("", "   ", "Value")  // empty/whitespace
            }
        };
        await _context.Items.AddAsync(item);
        await _context.SaveChangesAsync();

        // Act
        await _repository.SyncSuggestionsAsync(TestCollectionId, TestTenantId, Enumerable.Empty<string>(), Enumerable.Empty<string>());

        // Assert - no suggestions should be created for empty values
        Assert.Empty(await _context.PropertySuggestions.ToListAsync());
    }

    [Fact]
    public async Task SyncSuggestionsAsync_NormalizesCaseForComparison()
    {
        // Arrange
        var existingSuggestion = new PropertySuggestion
        {
            Id = 1,
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Type = PropertySuggestionType.Category,
            Value = "Category"
        };
        var item = new Item
        {
            Id = 1,
            TenantId = TestTenantId,
            CollectionId = TestCollectionId,
            Name = "Test Item",
            Properties = new List<ItemProperty>
            {
                new("CATEGORY", "Name", "Value")  // different case
            }
        };
        await _context.PropertySuggestions.AddAsync(existingSuggestion);
        await _context.Items.AddAsync(item);
        await _context.SaveChangesAsync();

        // Act
        await _repository.SyncSuggestionsAsync(TestCollectionId, TestTenantId, Enumerable.Empty<string>(), Enumerable.Empty<string>());

        // Assert - should keep existing and not duplicate
        var categorySuggestions = await _context.PropertySuggestions
            .Where(s => s.Type == PropertySuggestionType.Category)
            .ToListAsync();
        Assert.Single(categorySuggestions);
    }

    [Fact]
    public async Task SyncSuggestionsAsync_OnlyAffectsSpecifiedTenantAndCollection()
    {
        // Arrange
        var otherSuggestion = new PropertySuggestion
        {
            Id = 1,
            TenantId = OtherTenantId,
            CollectionId = TestCollectionId,
            Type = PropertySuggestionType.Category,
            Value = "OtherTenantCategory"
        };
        await _context.PropertySuggestions.AddAsync(otherSuggestion);
        await _context.SaveChangesAsync();

        // Act
        await _repository.SyncSuggestionsAsync(TestCollectionId, TestTenantId, Enumerable.Empty<string>(), Enumerable.Empty<string>());

        // Assert - other tenant's suggestion should not be affected
        var suggestion = await _context.PropertySuggestions.FindAsync(1);
        Assert.NotNull(suggestion);
        Assert.Equal("OtherTenantCategory", suggestion.Value);
    }

    #endregion
}
