using OneBigHead.Server.DTOs;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services;

[GenerateTracingProxy]
public interface IUserDeletionService
{
    Task<UserDeletionInfoResponse?> GetDeletionInfoAsync(int userId);
    Task<TransferAdminResponse> TransferAdminRoleAsync(int workspaceId, int fromUserId, int toUserId);
    Task<DeleteUserResponse> DeleteUserAccountAsync(int userId, DeleteUserRequest request);
}