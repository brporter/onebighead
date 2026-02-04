using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services;

public interface ITenantDeletionService
{
    Task<TenantStatsResponse?> GetTenantStatsAsync(int tenantId);
    Task<TenantDeletionResponse> SoftDeleteTenantAsync(int tenantId, int deletedByUserId);
    Task<bool> IsTenantDeletedAsync(int tenantId);
}

public class TenantDeletionService : ITenantDeletionService
{
    private readonly AppDbContext _context;
    private readonly ITenantRepository _tenantRepository;
    private readonly ITenantUserRepository _tenantUserRepository;
    private readonly IUserRepository _userRepository;
    private readonly ILogger<TenantDeletionService> _logger;

    public TenantDeletionService(
        AppDbContext context,
        ITenantRepository tenantRepository,
        ITenantUserRepository tenantUserRepository,
        IUserRepository userRepository,
        ILogger<TenantDeletionService> logger)
    {
        _context = context;
        _tenantRepository = tenantRepository;
        _tenantUserRepository = tenantUserRepository;
        _userRepository = userRepository;
        _logger = logger;
    }

    public async Task<TenantStatsResponse?> GetTenantStatsAsync(int tenantId)
    {
        var tenant = await _tenantRepository.GetByIdAsync(tenantId);
        if (tenant == null || tenant.IsDeleted)
        {
            return null;
        }

        var collectionCount = await _context.Collections.CountAsync(c => c.TenantId == tenantId);
        var categoryCount = await _context.Categories.CountAsync(c => c.TenantId == tenantId);
        var itemCount = await _context.Items.CountAsync(i => i.TenantId == tenantId);
        var imageCount = await _context.StoredImages.CountAsync(i => i.TenantId == tenantId);
        var userCount = await _tenantUserRepository.CountMembersInTenantAsync(tenantId);
        var adminCount = await _tenantUserRepository.CountAdminsInTenantAsync(tenantId);

        return new TenantStatsResponse
        {
            TenantId = tenantId,
            TenantName = tenant.Name,
            CollectionCount = collectionCount,
            CategoryCount = categoryCount,
            ItemCount = itemCount,
            ImageCount = imageCount,
            UserCount = userCount,
            AdminCount = adminCount
        };
    }

    public async Task<TenantDeletionResponse> SoftDeleteTenantAsync(int tenantId, int deletedByUserId)
    {
        var tenant = await _tenantRepository.GetByIdAsync(tenantId);
        if (tenant == null || tenant.IsDeleted)
        {
            return new TenantDeletionResponse { Success = false };
        }

        // Soft delete the tenant
        tenant.IsDeleted = true;
        tenant.DeletedAt = DateTime.UtcNow;
        tenant.DeletedByUserId = deletedByUserId;

        await _tenantRepository.UpdateAsync(tenant);

        _logger.LogInformation("Tenant {TenantId} ({TenantName}) soft-deleted by user {UserId}",
            tenantId, tenant.Name, deletedByUserId);

        // Get all users who had this as their active tenant and switch them
        var affectedUsers = await _context.Users
            .Where(u => u.ActiveTenantId == tenantId)
            .ToListAsync();

        int? newActiveTenantId = null;

        foreach (var user in affectedUsers)
        {
            // Find another tenant for this user
            var nextMembership = await _context.TenantUsers
                .Include(tu => tu.Tenant)
                .Where(tu => tu.UserId == user.Id && tu.TenantId != tenantId && !tu.Tenant!.IsDeleted)
                .FirstOrDefaultAsync();

            if (nextMembership != null)
            {
                await _userRepository.UpdateActiveTenantAsync(user.Id, nextMembership.TenantId);

                // Track the new tenant for the requesting user
                if (user.Id == deletedByUserId)
                {
                    newActiveTenantId = nextMembership.TenantId;
                }

                _logger.LogInformation("User {UserId} switched from deleted tenant {OldTenantId} to {NewTenantId}",
                    user.Id, tenantId, nextMembership.TenantId);
            }
            else
            {
                _logger.LogWarning("User {UserId} has no other tenants after tenant {TenantId} was deleted",
                    user.Id, tenantId);
            }
        }

        return new TenantDeletionResponse
        {
            Success = true,
            NewActiveTenantId = newActiveTenantId
        };
    }

    public async Task<bool> IsTenantDeletedAsync(int tenantId)
    {
        var tenant = await _tenantRepository.GetByIdAsync(tenantId);
        return tenant?.IsDeleted ?? true;
    }
}
