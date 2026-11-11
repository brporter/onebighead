using OneBigHead.Server.DTOs;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services.PublicCatalog;

/// <summary>Anonymous catalog projections. Null means the requested public resource does not exist.</summary>
[GenerateTracingProxy]
public interface IPublicCatalogReader
{
    Task<PublicWorkspaceDto?> GetWorkspaceAsync(string slug, CancellationToken cancellationToken);
    Task<List<PublicCollectionDto>?> GetCollectionsAsync(string slug, CancellationToken cancellationToken);
    Task<PublicCollectionDetailDto?> GetCollectionAsync(string slug, int collectionId, CancellationToken cancellationToken);
    Task<List<PublicItemSummaryDto>?> GetItemsAsync(string slug, int collectionId, int? categoryId, CancellationToken cancellationToken);
    Task<PublicItemDto?> GetItemAsync(string slug, int itemId, CancellationToken cancellationToken);
}
