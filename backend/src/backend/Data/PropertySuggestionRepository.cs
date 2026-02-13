using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class PropertySuggestionRepository : IPropertySuggestionRepository
{
    private readonly AppDbContext _context;

    public PropertySuggestionRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task<IEnumerable<PropertySuggestion>> GetByCollectionAsync(int collectionId, int workspaceId)
    {
        return await _context.PropertySuggestions
            .Where(p => p.CollectionId == collectionId && p.WorkspaceId == workspaceId)
            .OrderBy(p => p.Type)
            .ThenBy(p => p.Value)
            .ToListAsync();
    }

    public async Task<IEnumerable<string>> GetCategoriesAsync(int collectionId, int workspaceId)
    {
        return await _context.PropertySuggestions
            .Where(p => p.CollectionId == collectionId && p.WorkspaceId == workspaceId && p.Type == PropertySuggestionType.Category)
            .OrderBy(p => p.Value)
            .Select(p => p.Value)
            .ToListAsync();
    }

    public async Task<IEnumerable<string>> GetNamesAsync(int collectionId, int workspaceId)
    {
        return await _context.PropertySuggestions
            .Where(p => p.CollectionId == collectionId && p.WorkspaceId == workspaceId && p.Type == PropertySuggestionType.Name)
            .OrderBy(p => p.Value)
            .Select(p => p.Value)
            .ToListAsync();
    }

    public async Task SyncSuggestionsAsync(int collectionId, int workspaceId, IEnumerable<string> categories, IEnumerable<string> names)
    {
        // Get all items in the collection to determine which suggestions are still valid
        var itemsInCollection = await _context.Items
            .Where(i => i.CollectionId == collectionId && i.WorkspaceId == workspaceId)
            .ToListAsync();

        // Extract all unique property categories and names from items
        var usedCategories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var usedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var item in itemsInCollection)
        {
            foreach (var prop in item.Properties)
            {
                if (!string.IsNullOrWhiteSpace(prop.Category))
                {
                    usedCategories.Add(prop.Category.Trim());
                }
                if (!string.IsNullOrWhiteSpace(prop.Name))
                {
                    usedNames.Add(prop.Name.Trim());
                }
            }
        }

        // Get existing suggestions for this collection
        var existingSuggestions = await _context.PropertySuggestions
            .Where(p => p.CollectionId == collectionId && p.WorkspaceId == workspaceId)
            .ToListAsync();

        // Remove suggestions that are no longer used
        var suggestionsToRemove = existingSuggestions
            .Where(s =>
                (s.Type == PropertySuggestionType.Category && !usedCategories.Contains(s.Value)) ||
                (s.Type == PropertySuggestionType.Name && !usedNames.Contains(s.Value)))
            .ToList();

        if (suggestionsToRemove.Count > 0)
        {
            _context.PropertySuggestions.RemoveRange(suggestionsToRemove);
        }

        // Add new suggestions that don't exist yet
        var existingCategoryValues = existingSuggestions
            .Where(s => s.Type == PropertySuggestionType.Category)
            .Select(s => s.Value)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var existingNameValues = existingSuggestions
            .Where(s => s.Type == PropertySuggestionType.Name)
            .Select(s => s.Value)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var newSuggestions = new List<PropertySuggestion>();

        foreach (var category in usedCategories)
        {
            if (!existingCategoryValues.Contains(category))
            {
                newSuggestions.Add(new PropertySuggestion
                {
                    WorkspaceId = workspaceId,
                    CollectionId = collectionId,
                    Type = PropertySuggestionType.Category,
                    Value = category
                });
            }
        }

        foreach (var name in usedNames)
        {
            if (!existingNameValues.Contains(name))
            {
                newSuggestions.Add(new PropertySuggestion
                {
                    WorkspaceId = workspaceId,
                    CollectionId = collectionId,
                    Type = PropertySuggestionType.Name,
                    Value = name
                });
            }
        }

        if (newSuggestions.Count > 0)
        {
            await _context.PropertySuggestions.AddRangeAsync(newSuggestions);
        }

        await _context.SaveChangesAsync();
    }
}
