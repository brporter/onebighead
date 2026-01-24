using backend.Models;

namespace backend.Data;

public interface IItemTemplateRepository
{
    /// <summary>
    /// Gets all templates accessible to the user (shared + personal).
    /// </summary>
    Task<IEnumerable<ItemTemplate>> GetAllAccessibleAsync(int? tenantId, int? userId);
    
    /// <summary>
    /// Gets shared/global templates only.
    /// </summary>
    Task<IEnumerable<ItemTemplate>> GetSharedAsync();
    
    /// <summary>
    /// Gets personal templates for a specific user.
    /// </summary>
    Task<IEnumerable<ItemTemplate>> GetPersonalAsync(int tenantId, int userId);
    
    /// <summary>
    /// Gets a template by ID if accessible to the user.
    /// </summary>
    Task<ItemTemplate?> GetByIdAsync(int id, int? tenantId, int? userId);
    
    /// <summary>
    /// Gets templates associated with a collection.
    /// </summary>
    Task<IEnumerable<ItemTemplate>> GetByCollectionAsync(int collectionId);
    
    /// <summary>
    /// Creates a new template (personal or shared if tenantId/userId are null).
    /// </summary>
    Task<ItemTemplate> CreateAsync(ItemTemplate template);
    
    /// <summary>
    /// Updates a template. Only the owner can update personal templates.
    /// </summary>
    Task<ItemTemplate?> UpdateAsync(int id, ItemTemplate template, int? tenantId, int? userId);
    
    /// <summary>
    /// Deletes a template. Only the owner can delete personal templates.
    /// </summary>
    Task<bool> DeleteAsync(int id, int? tenantId, int? userId);
    
    /// <summary>
    /// Associates a template with a collection.
    /// </summary>
    Task<bool> AssociateWithCollectionAsync(int templateId, int collectionId);
    
    /// <summary>
    /// Removes a template association from a collection.
    /// </summary>
    Task<bool> DisassociateFromCollectionAsync(int templateId, int collectionId);
}
