using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class UserRepository : IUserRepository
{
    private readonly AppDbContext _context;

    public UserRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task<User?> GetByEmailAsync(string email)
    {
        return await _context.Users
            .Include(u => u.ActiveTenant)
            .FirstOrDefaultAsync(u => u.Email == email);
    }

    public async Task<User?> GetByProviderIdAsync(IdentityProvider provider, string providerSubjectId)
    {
        return await _context.Users
            .Include(u => u.ActiveTenant)
            .FirstOrDefaultAsync(u => u.IdentityProvider == provider && u.ProviderSubjectId == providerSubjectId);
    }

    public async Task<User?> GetByIdAsync(int id)
    {
        return await _context.Users
            .Include(u => u.ActiveTenant)
            .FirstOrDefaultAsync(u => u.Id == id);
    }

    public async Task<User?> GetByIdWithMembershipsAsync(int id)
    {
        return await _context.Users
            .Include(u => u.ActiveTenant)
            .Include(u => u.TenantMemberships)
                .ThenInclude(tm => tm.Tenant)
            .FirstOrDefaultAsync(u => u.Id == id);
    }

    public async Task<IEnumerable<User>> GetByTenantIdAsync(int tenantId)
    {
        // Get users who are members of this tenant via TenantUser
        var userIds = await _context.TenantUsers
            .Where(tu => tu.TenantId == tenantId)
            .Select(tu => tu.UserId)
            .ToListAsync();

        return await _context.Users
            .Include(u => u.ActiveTenant)
            .Where(u => userIds.Contains(u.Id))
            .OrderBy(u => u.CreatedAt)
            .ToListAsync();
    }

    public async Task<User> CreateWithNewTenantAsync(string email, IdentityProvider provider, string providerSubjectId)
    {
        await using var transaction = await _context.Database.BeginTransactionAsync();

        try
        {
            // Create tenant with name based on email domain
            var emailDomain = email.Contains('@') ? email.Split('@')[1] : email;
            var tenant = new Tenant
            {
                Name = emailDomain,
                CreatedAt = DateTime.UtcNow
            };

            _context.Tenants.Add(tenant);
            await _context.SaveChangesAsync();

            // Note: We no longer create a default collection here.
            // New users will be directed to the setup wizard to create their first collection.

            // Create user with this as their active tenant
            var user = new User
            {
                ActiveTenantId = tenant.Id,
                Email = email,
                IdentityProvider = provider,
                ProviderSubjectId = providerSubjectId,
                CreatedAt = DateTime.UtcNow
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            // Create the TenantUser membership - first user is TenantAdmin
            var tenantUser = new TenantUser
            {
                UserId = user.Id,
                TenantId = tenant.Id,
                TenantRole = TenantRole.TenantAdmin,
                CreatedAt = DateTime.UtcNow
            };

            _context.TenantUsers.Add(tenantUser);
            await _context.SaveChangesAsync();

            await transaction.CommitAsync();

            user.ActiveTenant = tenant;
            return user;
        }
        catch
        {
            await transaction.RollbackAsync();
            throw;
        }
    }

    public async Task<User> CreatePendingUserAsync(int tenantId, string email, TenantRole role)
    {
        await using var transaction = await _context.Database.BeginTransactionAsync();

        try
        {
            var user = new User
            {
                ActiveTenantId = tenantId,
                Email = email,
                IdentityProvider = IdentityProvider.None,
                ProviderSubjectId = null,
                CreatedAt = DateTime.UtcNow
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            // Create the TenantUser membership
            var tenantUser = new TenantUser
            {
                UserId = user.Id,
                TenantId = tenantId,
                TenantRole = role,
                CreatedAt = DateTime.UtcNow
            };

            _context.TenantUsers.Add(tenantUser);
            await _context.SaveChangesAsync();

            await transaction.CommitAsync();

            // Load tenant for response
            await _context.Entry(user).Reference(u => u.ActiveTenant).LoadAsync();

            return user;
        }
        catch
        {
            await transaction.RollbackAsync();
            throw;
        }
    }

    public async Task<User?> LinkUserAsync(int userId, IdentityProvider provider, string providerSubjectId)
    {
        var user = await _context.Users
            .Include(u => u.ActiveTenant)
            .FirstOrDefaultAsync(u => u.Id == userId);

        if (user == null)
        {
            return null;
        }

        user.IdentityProvider = provider;
        user.ProviderSubjectId = providerSubjectId;

        await _context.SaveChangesAsync();
        return user;
    }

    public async Task<bool> DeleteByIdAndTenantAsync(int userId, int tenantId)
    {
        // Delete the TenantUser membership
        var tenantUser = await _context.TenantUsers
            .FirstOrDefaultAsync(tu => tu.UserId == userId && tu.TenantId == tenantId);

        if (tenantUser == null)
        {
            return false;
        }

        _context.TenantUsers.Remove(tenantUser);

        // Check if this was the user's only membership
        var remainingMemberships = await _context.TenantUsers
            .CountAsync(tu => tu.UserId == userId && tu.TenantId != tenantId);

        if (remainingMemberships == 0)
        {
            // If no remaining memberships, delete the user entirely
            var user = await _context.Users.FindAsync(userId);
            if (user != null)
            {
                _context.Users.Remove(user);
            }
        }
        else
        {
            // If user was viewing this tenant, switch to another
            var user = await _context.Users.FindAsync(userId);
            if (user != null && user.ActiveTenantId == tenantId)
            {
                var nextMembership = await _context.TenantUsers
                    .Where(tu => tu.UserId == userId && tu.TenantId != tenantId)
                    .OrderBy(tu => tu.CreatedAt)
                    .FirstAsync();
                user.ActiveTenantId = nextMembership.TenantId;
            }
        }

        await _context.SaveChangesAsync();
        return true;
    }

    public async Task UpdateAsync(User user)
    {
        _context.Users.Update(user);
        await _context.SaveChangesAsync();
    }

    public async Task UpdateActiveTenantAsync(int userId, int tenantId)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user != null)
        {
            user.ActiveTenantId = tenantId;
            await _context.SaveChangesAsync();
        }
    }
}

