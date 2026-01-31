using OneBigHead.Server.Models;

namespace OneBigHead.Server.Data;

public interface IPropertySuggestionRepository
{
    Task<IEnumerable<PropertySuggestion>> GetByCollectionAsync(int collectionId, int tenantId);
    Task<IEnumerable<string>> GetCategoriesAsync(int collectionId, int tenantId);
    Task<IEnumerable<string>> GetNamesAsync(int collectionId, int tenantId);
    Task SyncSuggestionsAsync(int collectionId, int tenantId, IEnumerable<string> categories, IEnumerable<string> names);
}
