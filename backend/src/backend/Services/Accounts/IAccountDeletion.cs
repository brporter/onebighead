using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Accounts;

public enum AccountDeletionStatus { Deleted, Invalid, Conflict }

public sealed record AccountDeletionResult(AccountDeletionStatus Status, string? Error = null);

public interface IAccountDeletion
{
    Task<AccountDeletionResult> DeleteAsync(int userId, DeleteUserRequest request);
}
