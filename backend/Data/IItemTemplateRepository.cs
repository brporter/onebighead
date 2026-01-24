using backend.Models;

namespace backend.Data;

public interface IItemTemplateRepository
{
    /// <summary>
    /// Gets all templates accessible to the tenant (shared + tenant-owned).
    /// </summary>
    Task<IEnumerable<ItemTemplate>> GetAllAccessibleAsync(int tenantId);
    
    /// <summary>
    /// Gets shared/system templates only.
    /// </summary>
    Task<IEnumerable<ItemTemplate>> GetSharedAsync();
    
    /// <summary>
    /// Gets tenant-owned templates.
    /// </summary>
    Task<IEnumerable<ItemTemplate>> GetTenantTemplatesAsync(int tenantId);
    
    /// <summary>
    /// Gets a template by ID if accessible to the tenant.
    /// </summary>
    Task<ItemTemplate?> GetByIdAsync(int id, int tenantId);
    
    /// <summary>
    /// Gets templates associated with a collection.
    /// </summary>
    Task<IEnumerable<ItemTemplate>> GetByCollectionAsync(int collectionId);
    
    /// <summary>
    /// Creates a new tenant-owned template.
    /// </summary>
    Task<ItemTemplate> CreateAsync(ItemTemplate template);
    
    /// <summary>
    /// Updates a template. Only tenant-owned templates can be updated.
    /// </summary>
    Task<ItemTemplate?> UpdateAsync(int id, ItemTemplate template, int tenantId);
    
    /// <summary>
    /// Deletes a template. Only tenant-owned templates can be deleted.
    /// </summary>
    Task<bool> DeleteAsync(int id, int tenantId);
    
    /// <summary>
    /// Associates a template with a collection.
    /// </summary>
    Task<bool> AssociateWithCollectionAsync(int templateId, int collectionId);
    
    /// <summary>
    /// Removes a template association from a collection.
    /// </summary>
    Task<bool> DisassociateFromCollectionAsync(int templateId, int collectionId);
}
