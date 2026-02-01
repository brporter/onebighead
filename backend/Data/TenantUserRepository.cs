using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class TenantUserRepository : ITenantUserRepository
{
    private readonly AppDbContext _context;

    public TenantUserRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task<TenantUser?> GetMembershipAsync(int userId, int tenantId)
    {
        return await _context.TenantUsers
            .Include(tu => tu.Tenant)
            .Include(tu => tu.User)
            .FirstOrDefaultAsync(tu => tu.UserId == userId && tu.TenantId == tenantId);
    }

    public async Task<IEnumerable<TenantUser>> GetByUserIdAsync(int userId)
    {
        return await _context.TenantUsers
            .Include(tu => tu.Tenant)
            .Where(tu => tu.UserId == userId)
            .OrderBy(tu => tu.CreatedAt)
            .ToListAsync();
    }

    public async Task<IEnumerable<TenantUser>> GetByTenantIdAsync(int tenantId)
    {
        return await _context.TenantUsers
            .Include(tu => tu.User)
            .Where(tu => tu.TenantId == tenantId)
            .OrderBy(tu => tu.CreatedAt)
            .ToListAsync();
    }

    public async Task<TenantUser> CreateAsync(int userId, int tenantId, TenantRole role)
    {
        var tenantUser = new TenantUser
        {
            UserId = userId,
            TenantId = tenantId,
            TenantRole = role,
            CreatedAt = DateTime.UtcNow
        };

        _context.TenantUsers.Add(tenantUser);
        await _context.SaveChangesAsync();

        // Load related entities
        await _context.Entry(tenantUser).Reference(tu => tu.Tenant).LoadAsync();
        await _context.Entry(tenantUser).Reference(tu => tu.User).LoadAsync();

        return tenantUser;
    }

    public async Task<bool> UpdateRoleAsync(int userId, int tenantId, TenantRole role)
    {
        var tenantUser = await _context.TenantUsers
            .FirstOrDefaultAsync(tu => tu.UserId == userId && tu.TenantId == tenantId);

        if (tenantUser == null)
        {
            return false;
        }

        tenantUser.TenantRole = role;
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<bool> DeleteAsync(int userId, int tenantId)
    {
        var tenantUser = await _context.TenantUsers
            .FirstOrDefaultAsync(tu => tu.UserId == userId && tu.TenantId == tenantId);

        if (tenantUser == null)
        {
            return false;
        }

        _context.TenantUsers.Remove(tenantUser);
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<int> CountAdminsInTenantAsync(int tenantId)
    {
        return await _context.TenantUsers
            .CountAsync(tu => tu.TenantId == tenantId && tu.TenantRole == TenantRole.TenantAdmin);
    }

    public async Task<int> CountMembersInTenantAsync(int tenantId)
    {
        return await _context.TenantUsers
            .CountAsync(tu => tu.TenantId == tenantId);
    }

    public async Task<int> CountUserMembershipsAsync(int userId)
    {
        return await _context.TenantUsers
            .CountAsync(tu => tu.UserId == userId);
    }
}
