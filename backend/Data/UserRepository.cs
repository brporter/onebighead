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
            .Include(u => u.ActiveWorkspace)
            .FirstOrDefaultAsync(u => u.Email == email);
    }

    public async Task<User?> GetByProviderIdAsync(IdentityProvider provider, string providerSubjectId)
    {
        return await _context.Users
            .Include(u => u.ActiveWorkspace)
            .FirstOrDefaultAsync(u => u.IdentityProvider == provider && u.ProviderSubjectId == providerSubjectId);
    }

    public async Task<User?> GetByIdAsync(int id)
    {
        return await _context.Users
            .Include(u => u.ActiveWorkspace)
            .FirstOrDefaultAsync(u => u.Id == id);
    }

    public async Task<User?> GetByIdWithMembershipsAsync(int id)
    {
        return await _context.Users
            .Include(u => u.ActiveWorkspace)
            .Include(u => u.WorkspaceMemberships)
                .ThenInclude(wm => wm.Workspace)
            .FirstOrDefaultAsync(u => u.Id == id);
    }

    public async Task<IEnumerable<User>> GetByWorkspaceIdAsync(int workspaceId)
    {
        // Get users who are members of this workspace via WorkspaceUser
        var userIds = await _context.WorkspaceUsers
            .Where(wu => wu.WorkspaceId == workspaceId)
            .Select(wu => wu.UserId)
            .ToListAsync();

        return await _context.Users
            .Include(u => u.ActiveWorkspace)
            .Where(u => userIds.Contains(u.Id))
            .OrderBy(u => u.CreatedAt)
            .ToListAsync();
    }

    public async Task<User> CreateWithNewWorkspaceAsync(string email, IdentityProvider provider, string providerSubjectId)
    {
        await using var transaction = await _context.Database.BeginTransactionAsync();

        try
        {
            // Create workspace with name based on email domain
            var emailDomain = email.Contains('@') ? email.Split('@')[1] : email;
            var workspace = new Workspace
            {
                Name = emailDomain,
                CreatedAt = DateTime.UtcNow
            };

            _context.Workspaces.Add(workspace);
            await _context.SaveChangesAsync();

            // Note: We no longer create a default collection here.
            // New users will be directed to the setup wizard to create their first collection.

            // Create user with this as their active workspace
            var user = new User
            {
                ActiveWorkspaceId = workspace.Id,
                Email = email,
                IdentityProvider = provider,
                ProviderSubjectId = providerSubjectId,
                CreatedAt = DateTime.UtcNow
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            // Create the WorkspaceUser membership - first user is WorkspaceAdmin
            var workspaceUser = new WorkspaceUser
            {
                UserId = user.Id,
                WorkspaceId = workspace.Id,
                WorkspaceRole = WorkspaceRole.WorkspaceAdmin,
                CreatedAt = DateTime.UtcNow
            };

            _context.WorkspaceUsers.Add(workspaceUser);
            await _context.SaveChangesAsync();

            await transaction.CommitAsync();

            user.ActiveWorkspace = workspace;
            return user;
        }
        catch
        {
            await transaction.RollbackAsync();
            throw;
        }
    }

    public async Task<User> CreatePendingUserAsync(int workspaceId, string email, WorkspaceRole role)
    {
        await using var transaction = await _context.Database.BeginTransactionAsync();

        try
        {
            var user = new User
            {
                ActiveWorkspaceId = workspaceId,
                Email = email,
                IdentityProvider = IdentityProvider.None,
                ProviderSubjectId = null,
                CreatedAt = DateTime.UtcNow
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            // Create the WorkspaceUser membership
            var workspaceUser = new WorkspaceUser
            {
                UserId = user.Id,
                WorkspaceId = workspaceId,
                WorkspaceRole = role,
                CreatedAt = DateTime.UtcNow
            };

            _context.WorkspaceUsers.Add(workspaceUser);
            await _context.SaveChangesAsync();

            await transaction.CommitAsync();

            // Load workspace for response
            await _context.Entry(user).Reference(u => u.ActiveWorkspace).LoadAsync();

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
            .Include(u => u.ActiveWorkspace)
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

    public async Task<bool> DeleteByIdAndWorkspaceAsync(int userId, int workspaceId)
    {
        // Delete the WorkspaceUser membership
        var workspaceUser = await _context.WorkspaceUsers
            .FirstOrDefaultAsync(wu => wu.UserId == userId && wu.WorkspaceId == workspaceId);

        if (workspaceUser == null)
        {
            return false;
        }

        _context.WorkspaceUsers.Remove(workspaceUser);

        // Check if this was the user's only membership
        var remainingMemberships = await _context.WorkspaceUsers
            .CountAsync(wu => wu.UserId == userId && wu.WorkspaceId != workspaceId);

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
            // If user was viewing this workspace, switch to another
            var user = await _context.Users.FindAsync(userId);
            if (user != null && user.ActiveWorkspaceId == workspaceId)
            {
                var nextMembership = await _context.WorkspaceUsers
                    .Where(wu => wu.UserId == userId && wu.WorkspaceId != workspaceId)
                    .OrderBy(wu => wu.CreatedAt)
                    .FirstAsync();
                user.ActiveWorkspaceId = nextMembership.WorkspaceId;
            }
        }

        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<bool> DeleteAsync(int userId)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user == null)
        {
            return false;
        }

        _context.Users.Remove(user);
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task UpdateAsync(User user)
    {
        _context.Users.Update(user);
        await _context.SaveChangesAsync();
    }

    public async Task UpdateActiveWorkspaceAsync(int userId, int workspaceId)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user != null)
        {
            user.ActiveWorkspaceId = workspaceId;
            await _context.SaveChangesAsync();
        }
    }
}

