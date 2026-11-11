namespace OneBigHead.Server.Services.Administration;

public enum AdministratorWorkspaceDeletionResult { Deleted, NotFound, ConflictingReferences, ConcurrentChange }

public interface IAdministratorWorkspaceDeletion
{
    Task<AdministratorWorkspaceDeletionResult> DeleteAsync(int workspaceId);
}
