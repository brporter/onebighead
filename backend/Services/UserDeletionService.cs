using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services;

public interface IUserDeletionService
{
    Task<UserDeletionInfoResponse?> GetDeletionInfoAsync(int userId);
    Task<TransferAdminResponse> TransferAdminRoleAsync(int tenantId, int fromUserId, int toUserId);
    Task<DeleteUserResponse> DeleteUserAccountAsync(int userId, DeleteUserRequest request);
}

public class UserDeletionService : IUserDeletionService
{
    private readonly AppDbContext _context;
    private readonly IUserRepository _userRepository;
    private readonly ITenantUserRepository _tenantUserRepository;
    private readonly ITenantDeletionService _tenantDeletionService;
    private readonly ILogger<UserDeletionService> _logger;

    public UserDeletionService(
        AppDbContext context,
        IUserRepository userRepository,
        ITenantUserRepository tenantUserRepository,
        ITenantDeletionService tenantDeletionService,
        ILogger<UserDeletionService> logger)
    {
        _context = context;
        _userRepository = userRepository;
        _tenantUserRepository = tenantUserRepository;
        _tenantDeletionService = tenantDeletionService;
        _logger = logger;
    }

    public async Task<UserDeletionInfoResponse?> GetDeletionInfoAsync(int userId)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            return null;
        }

        var memberships = await _tenantUserRepository.GetByUserIdAsync(userId);
        var membershipInfos = new List<TenantMembershipDeletionInfo>();
        var tenantsRequiringAction = 0;

        foreach (var membership in memberships)
        {
            // Skip deleted tenants
            if (membership.Tenant?.IsDeleted == true)
            {
                continue;
            }

            var userCount = await _tenantUserRepository.CountMembersInTenantAsync(membership.TenantId);
            var adminCount = await _tenantUserRepository.CountAdminsInTenantAsync(membership.TenantId);
            var isOnlyUser = userCount == 1;
            var isOnlyAdmin = membership.TenantRole == TenantRole.TenantAdmin && adminCount == 1 && userCount > 1;

            var blockerReason = DeletionBlockerReason.None;
            var canLeave = true;

            if (isOnlyUser)
            {
                blockerReason = DeletionBlockerReason.SoleUser;
                canLeave = false;
                tenantsRequiringAction++;
            }
            else if (isOnlyAdmin)
            {
                blockerReason = DeletionBlockerReason.SoleAdmin;
                canLeave = false;
                tenantsRequiringAction++;
            }

            // Get other users in the tenant for admin transfer selection
            var otherUsers = new List<UserBasicInfo>();
            if (isOnlyAdmin)
            {
                var tenantUsers = await _context.TenantUsers
                    .Include(tu => tu.User)
                    .Where(tu => tu.TenantId == membership.TenantId && tu.UserId != userId)
                    .ToListAsync();

                otherUsers = tenantUsers
                    .Where(tu => tu.User != null)
                    .Select(tu => new UserBasicInfo
                    {
                        UserId = tu.UserId,
                        Email = tu.User!.Email
                    })
                    .ToList();
            }

            membershipInfos.Add(new TenantMembershipDeletionInfo
            {
                TenantId = membership.TenantId,
                TenantName = membership.Tenant?.Name ?? "Unknown",
                Role = membership.TenantRole,
                IsOnlyUser = isOnlyUser,
                IsOnlyAdmin = isOnlyAdmin,
                UserCount = userCount,
                CanLeave = canLeave,
                BlockerReason = blockerReason,
                OtherUsers = otherUsers
            });
        }

        return new UserDeletionInfoResponse
        {
            UserId = userId,
            Email = user.Email,
            TenantMemberships = membershipInfos,
            TenantsRequiringAction = tenantsRequiringAction,
            CanDeleteImmediately = tenantsRequiringAction == 0
        };
    }

    public async Task<TransferAdminResponse> TransferAdminRoleAsync(int tenantId, int fromUserId, int toUserId)
    {
        // Verify the from user is an admin
        var fromMembership = await _tenantUserRepository.GetMembershipAsync(fromUserId, tenantId);
        if (fromMembership == null || fromMembership.TenantRole != TenantRole.TenantAdmin)
        {
            return new TransferAdminResponse
            {
                Success = false,
                Error = "You are not an admin of this tenant"
            };
        }

        // Verify the to user is a member of the tenant
        var toMembership = await _tenantUserRepository.GetMembershipAsync(toUserId, tenantId);
        if (toMembership == null)
        {
            return new TransferAdminResponse
            {
                Success = false,
                Error = "Target user is not a member of this tenant"
            };
        }

        // Promote the target user to admin
        await _tenantUserRepository.UpdateRoleAsync(toUserId, tenantId, TenantRole.TenantAdmin);

        // Demote the from user to member
        await _tenantUserRepository.UpdateRoleAsync(fromUserId, tenantId, TenantRole.Normal);

        _logger.LogInformation("Admin role transferred in tenant {TenantId} from user {FromUserId} to user {ToUserId}",
            tenantId, fromUserId, toUserId);

        return new TransferAdminResponse { Success = true };
    }

    public async Task<DeleteUserResponse> DeleteUserAccountAsync(int userId, DeleteUserRequest request)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            return new DeleteUserResponse
            {
                Success = false,
                Error = "User not found"
            };
        }

        // Verify email confirmation
        if (!string.Equals(request.ConfirmEmail, user.Email, StringComparison.OrdinalIgnoreCase))
        {
            return new DeleteUserResponse
            {
                Success = false,
                Error = "Email confirmation does not match your account email"
            };
        }

        // Get current deletion info to check for unresolved blockers
        var deletionInfo = await GetDeletionInfoAsync(userId);
        if (deletionInfo == null)
        {
            return new DeleteUserResponse
            {
                Success = false,
                Error = "Unable to retrieve deletion info"
            };
        }

        // Process each tenant that requires action
        var actionsByTenant = request.TenantActions.ToDictionary(a => a.TenantId);

        foreach (var membership in deletionInfo.TenantMemberships.Where(m => !m.CanLeave))
        {
            if (!actionsByTenant.TryGetValue(membership.TenantId, out var action))
            {
                return new DeleteUserResponse
                {
                    Success = false,
                    Error = $"Missing action for tenant: {membership.TenantName}"
                };
            }

            if (membership.BlockerReason == DeletionBlockerReason.SoleUser)
            {
                // Must delete the tenant
                if (action.Action != TenantActionType.Delete)
                {
                    return new DeleteUserResponse
                    {
                        Success = false,
                        Error = $"Tenant '{membership.TenantName}' must be deleted since you are the only member"
                    };
                }

                var deleteResult = await _tenantDeletionService.SoftDeleteTenantAsync(membership.TenantId, userId);
                if (!deleteResult.Success)
                {
                    return new DeleteUserResponse
                    {
                        Success = false,
                        Error = $"Failed to delete tenant: {membership.TenantName}"
                    };
                }

                _logger.LogInformation("Tenant {TenantId} deleted as part of user {UserId} account deletion",
                    membership.TenantId, userId);
            }
            else if (membership.BlockerReason == DeletionBlockerReason.SoleAdmin)
            {
                // Must transfer admin
                if (action.Action != TenantActionType.Transfer || !action.TransferToUserId.HasValue)
                {
                    return new DeleteUserResponse
                    {
                        Success = false,
                        Error = $"Admin role must be transferred for tenant: {membership.TenantName}"
                    };
                }

                var transferResult = await TransferAdminRoleAsync(membership.TenantId, userId, action.TransferToUserId.Value);
                if (!transferResult.Success)
                {
                    return new DeleteUserResponse
                    {
                        Success = false,
                        Error = $"Failed to transfer admin for tenant '{membership.TenantName}': {transferResult.Error}"
                    };
                }

                _logger.LogInformation("Admin role transferred from user {UserId} to user {ToUserId} in tenant {TenantId} as part of account deletion",
                    userId, action.TransferToUserId.Value, membership.TenantId);
            }
        }

        // Remove user from all remaining tenants
        var memberships = await _tenantUserRepository.GetByUserIdAsync(userId);
        foreach (var membership in memberships)
        {
            await _tenantUserRepository.DeleteAsync(userId, membership.TenantId);
            _logger.LogInformation("Removed user {UserId} from tenant {TenantId} during account deletion",
                userId, membership.TenantId);
        }

        // Delete the user account
        var deleted = await _userRepository.DeleteAsync(userId);
        if (!deleted)
        {
            return new DeleteUserResponse
            {
                Success = false,
                Error = "Failed to delete user account"
            };
        }

        _logger.LogInformation("User account {UserId} ({Email}) deleted", userId, user.Email);

        return new DeleteUserResponse { Success = true };
    }
}
