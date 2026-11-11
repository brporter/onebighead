using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Collections;

public interface ICollectionSetupService
{
    Task<Collection> CreateAsync(Collection collection, CollectionTheme? theme);
}
