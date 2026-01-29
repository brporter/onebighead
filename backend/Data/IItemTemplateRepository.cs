using backend.Models;

namespace backend.Data;

public interface IItemTemplateRepository
{
    /// <summary>
    /// Gets all templates accessible to the tenant (system + tenant-owned).
    /// System templates are excluded if a tenant template with the same name exists.
    /// </summary>
    Task<IEnumerable<ItemTemplate>> GetAllAccessibleAsync(int tenantId);
    
    /// <summary>
    /// Gets system templates only (excludes those overridden by tenant templates).
    /// </summary>
    Task<IEnumerable<ItemTemplate>> GetSystemTemplatesAsync(int tenantId);
    
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
    /// Updates a template. Only tenant-owned templates can be updated directly.
    /// </summary>
    Task<ItemTemplate?> UpdateAsync(int id, ItemTemplate template, int tenantId);
    
    /// <summary>
    /// Copies a system template to the tenant's library.
    /// </summary>
    Task<ItemTemplate> CopySystemTemplateAsync(int systemTemplateId, int tenantId, ItemTemplate updates);
    
    /// <summary>
    /// Deletes a template. Only tenant-owned templates can be deleted.
    /// </summary>
    Task<bool> DeleteAsync(int id, int tenantId);
    
    /// <summary>
    /// Associates a template with a collection.
    /// </summary>
    Task<bool> AssociateWithCollectionAsync(int templateId, int collectionId);
    
    /// <summary>
    /// Associates multiple templates with a collection in a single batch operation.
    /// </summary>
    Task AssociateMultipleWithCollectionAsync(IEnumerable<int> templateIds, int collectionId);
    
    /// <summary>
    /// Removes a template association from a collection.
    /// </summary>
    Task<bool> DisassociateFromCollectionAsync(int templateId, int collectionId);
}
