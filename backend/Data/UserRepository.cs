using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Data;

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

            // Create user associated with the new tenant
            var user = new User
            {
                TenantId = tenant.Id,
                Email = email,
                IdentityProvider = provider,
                ProviderSubjectId = providerSubjectId,
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
}

