using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services;

public interface ICollectionSetupService
{
    Task<Collection> CreateAsync(Collection collection, CollectionTheme? theme);
    Task<Collection> SetupWorkspaceAsync(int userId, Workspace workspace, Collection collection, CollectionTheme? theme);
}
