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
            .Include(u => u.Tenant)
            .FirstOrDefaultAsync(u => u.Email == email);
    }

    public async Task<User?> GetByProviderIdAsync(IdentityProvider provider, string providerSubjectId)
    {
        return await _context.Users
            .Include(u => u.Tenant)
            .FirstOrDefaultAsync(u => u.IdentityProvider == provider && u.ProviderSubjectId == providerSubjectId);
    }

    public async Task<User?> GetByIdAsync(int id)
    {
        return await _context.Users
            .Include(u => u.Tenant)
            .FirstOrDefaultAsync(u => u.Id == id);
    }

    public async Task<IEnumerable<User>> GetByTenantIdAsync(int tenantId)
    {
        return await _context.Users
            .Include(u => u.Tenant)
            .Where(u => u.TenantId == tenantId)
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

            // Create user associated with the new tenant - first user is TenantAdmin
            var user = new User
            {
                TenantId = tenant.Id,
                Email = email,
                IdentityProvider = provider,
                ProviderSubjectId = providerSubjectId,
                TenantRole = TenantRole.TenantAdmin,
                CreatedAt = DateTime.UtcNow
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            await transaction.CommitAsync();

            user.Tenant = tenant;
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
        var user = new User
        {
            TenantId = tenantId,
            Email = email,
            IdentityProvider = IdentityProvider.None,
            ProviderSubjectId = null,
            TenantRole = role,
            CreatedAt = DateTime.UtcNow
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Load tenant for response
        await _context.Entry(user).Reference(u => u.Tenant).LoadAsync();

        return user;
    }

    public async Task<User?> LinkUserAsync(int userId, IdentityProvider provider, string providerSubjectId)
    {
        var user = await _context.Users
            .Include(u => u.Tenant)
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

    public async Task<bool> UpdateRoleAsync(int userId, int tenantId, TenantRole role)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Id == userId && u.TenantId == tenantId);

        if (user == null)
        {
            return false;
        }

        user.TenantRole = role;
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<bool> DeleteByIdAndTenantAsync(int userId, int tenantId)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Id == userId && u.TenantId == tenantId);

        if (user == null)
        {
            return false;
        }

        _context.Users.Remove(user);
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<int> CountAdminsInTenantAsync(int tenantId)
    {
        return await _context.Users
            .CountAsync(u => u.TenantId == tenantId && u.TenantRole == TenantRole.TenantAdmin);
    }

    public async Task UpdateAsync(User user)
    {
        _context.Users.Update(user);
        await _context.SaveChangesAsync();
    }
}

