namespace OneBigHead.Server.Services.Collections;

public interface ICollectionDeletion
{
    Task<CollectionWriteResult> DeleteAsync(int userId, int workspaceId, int collectionId, CancellationToken cancellationToken);
}
