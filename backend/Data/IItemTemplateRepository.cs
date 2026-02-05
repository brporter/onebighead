using OneBigHead.Server.Models;

namespace OneBigHead.Server.Data;

public interface IItemTemplateRepository
{
    /// <summary>
    /// Gets all templates accessible to the workspace (system + workspace-owned).
    /// System templates are excluded if a workspace template with the same name exists.
    /// </summary>
    Task<IEnumerable<ItemTemplate>> GetAllAccessibleAsync(int workspaceId);

    /// <summary>
    /// Gets system templates only (excludes those overridden by workspace templates).
    /// </summary>
    Task<IEnumerable<ItemTemplate>> GetSystemTemplatesAsync(int workspaceId);

    /// <summary>
    /// Gets workspace-owned templates.
    /// </summary>
    Task<IEnumerable<ItemTemplate>> GetWorkspaceTemplatesAsync(int workspaceId);

    /// <summary>
    /// Gets a template by ID if accessible to the workspace.
    /// </summary>
    Task<ItemTemplate?> GetByIdAsync(int id, int workspaceId);

    /// <summary>
    /// Gets templates associated with a collection.
    /// </summary>
    Task<IEnumerable<ItemTemplate>> GetByCollectionAsync(int collectionId);

    /// <summary>
    /// Creates a new workspace-owned template.
    /// </summary>
    Task<ItemTemplate> CreateAsync(ItemTemplate template);

    /// <summary>
    /// Updates a template. Only workspace-owned templates can be updated directly.
    /// </summary>
    Task<ItemTemplate?> UpdateAsync(int id, ItemTemplate template, int workspaceId);

    /// <summary>
    /// Copies a system template to the workspace's library.
    /// </summary>
    Task<ItemTemplate> CopySystemTemplateAsync(int systemTemplateId, int workspaceId, ItemTemplate updates);

    /// <summary>
    /// Deletes a template. Only workspace-owned templates can be deleted.
    /// </summary>
    Task<bool> DeleteAsync(int id, int workspaceId);

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
