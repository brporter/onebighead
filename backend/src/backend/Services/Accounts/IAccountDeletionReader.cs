using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Accounts;

public interface IAccountDeletionReader
{
    Task<UserDeletionInfoResponse?> ReadAsync(int userId);
}
