using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Collections;

public interface ICollectionDetails
{
    Task<CollectionWriteResult> UpdateAsync(int userId, int workspaceId, int collectionId, UpdateCollectionRequest request, CancellationToken cancellationToken);
}
