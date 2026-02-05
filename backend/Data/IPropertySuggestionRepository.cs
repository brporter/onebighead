using OneBigHead.Server.Models;

namespace OneBigHead.Server.Data;

public interface IPropertySuggestionRepository
{
    Task<IEnumerable<PropertySuggestion>> GetByCollectionAsync(int collectionId, int workspaceId);
    Task<IEnumerable<string>> GetCategoriesAsync(int collectionId, int workspaceId);
    Task<IEnumerable<string>> GetNamesAsync(int collectionId, int workspaceId);
    Task SyncSuggestionsAsync(int collectionId, int workspaceId, IEnumerable<string> categories, IEnumerable<string> names);
}
