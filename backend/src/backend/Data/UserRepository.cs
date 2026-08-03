using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class UserRepository : IUserRepository
{
    private readonly IDbContextFactory<AppDbContext> _contextFactory;

    public UserRepository(IDbContextFactory<AppDbContext> contextFactory)
    {
        _contextFactory = contextFactory;
    }

    public async Task<User?> GetByEmailAsync(string email)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Users
            .Include(u => u.ActiveWorkspace)
            .FirstOrDefaultAsync(u => u.Email == email);
    }

    public async Task<User?> GetByProviderIdAsync(IdentityProvider provider, string providerSubjectId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Users
            .Include(u => u.ActiveWorkspace)
            .FirstOrDefaultAsync(u => u.IdentityProvider == provider && u.ProviderSubjectId == providerSubjectId);
    }

    public async Task<User?> GetByIdAsync(int id)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Users
            .Include(u => u.ActiveWorkspace)
            .FirstOrDefaultAsync(u => u.Id == id);
    }

    public async Task<User?> GetByIdWithMembershipsAsync(int id)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Users
            .Include(u => u.ActiveWorkspace)
            .Include(u => u.WorkspaceMemberships)
                .ThenInclude(wm => wm.Workspace)
            .FirstOrDefaultAsync(u => u.Id == id);
    }

    public async Task<IEnumerable<User>> GetByWorkspaceIdAsync(int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        // Get users who are members of this workspace via WorkspaceUser
        var userIds = await context.WorkspaceUsers
            .Where(wu => wu.WorkspaceId == workspaceId)
            .Select(wu => wu.UserId)
            .ToListAsync();

        return await context.Users
            .Include(u => u.ActiveWorkspace)
            .Where(u => userIds.Contains(u.Id))
            .OrderBy(u => u.CreatedAt)
            .ToListAsync();
    }

    public async Task<User> CreateWithNewWorkspaceAsync(string email, IdentityProvider provider, string providerSubjectId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        await using var transaction = await context.Database.BeginTransactionAsync();

        try
        {
            // Create workspace with name based on email domain
            var emailDomain = email.Contains('@') ? email.Split('@')[1] : email;
            var workspace = new Workspace
            {
                Name = emailDomain,
                CreatedAt = DateTime.UtcNow
            };

            context.Workspaces.Add(workspace);
            await context.SaveChangesAsync();

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

            context.Users.Add(user);
            await context.SaveChangesAsync();

            // Create the WorkspaceUser membership - first user is WorkspaceAdmin
            var workspaceUser = new WorkspaceUser
            {
                UserId = user.Id,
                WorkspaceId = workspace.Id,
                WorkspaceRole = WorkspaceRole.WorkspaceAdmin,
                CreatedAt = DateTime.UtcNow
            };

            context.WorkspaceUsers.Add(workspaceUser);
            await context.SaveChangesAsync();

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
        await using var context = await _contextFactory.CreateDbContextAsync();
        await using var transaction = await context.Database.BeginTransactionAsync();

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

            context.Users.Add(user);
            await context.SaveChangesAsync();

            // Create the WorkspaceUser membership
            var workspaceUser = new WorkspaceUser
            {
                UserId = user.Id,
                WorkspaceId = workspaceId,
                WorkspaceRole = role,
                CreatedAt = DateTime.UtcNow
            };

            context.WorkspaceUsers.Add(workspaceUser);
            await context.SaveChangesAsync();

            await transaction.CommitAsync();

            // Load workspace for response
            await context.Entry(user).Reference(u => u.ActiveWorkspace).LoadAsync();

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
        await using var context = await _contextFactory.CreateDbContextAsync();
        var user = await context.Users
            .Include(u => u.ActiveWorkspace)
            .FirstOrDefaultAsync(u => u.Id == userId);

        if (user == null)
        {
            return null;
        }

        user.IdentityProvider = provider;
        user.ProviderSubjectId = providerSubjectId;

        await context.SaveChangesAsync();
        return user;
    }

    public async Task<bool> DeleteByIdAndWorkspaceAsync(int userId, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        // Delete the WorkspaceUser membership
        var workspaceUser = await context.WorkspaceUsers
            .FirstOrDefaultAsync(wu => wu.UserId == userId && wu.WorkspaceId == workspaceId);

        if (workspaceUser == null)
        {
            return false;
        }

        context.WorkspaceUsers.Remove(workspaceUser);

        // Check if this was the user's only membership
        var remainingMemberships = await context.WorkspaceUsers
            .CountAsync(wu => wu.UserId == userId && wu.WorkspaceId != workspaceId);

        if (remainingMemberships == 0)
        {
            // If no remaining memberships, delete the user entirely
            var user = await context.Users.FindAsync(userId);
            if (user != null)
            {
                context.Users.Remove(user);
            }
        }
        else
        {
            // If user was viewing this workspace, switch to another
            var user = await context.Users.FindAsync(userId);
            if (user != null && user.ActiveWorkspaceId == workspaceId)
            {
                var nextMembership = await context.WorkspaceUsers
                    .Where(wu => wu.UserId == userId && wu.WorkspaceId != workspaceId)
                    .OrderBy(wu => wu.CreatedAt)
                    .FirstAsync();
                user.ActiveWorkspaceId = nextMembership.WorkspaceId;
            }
        }

        await context.SaveChangesAsync();
        return true;
    }

    public async Task<bool> DeleteAsync(int userId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var user = await context.Users.FindAsync(userId);
        if (user == null)
        {
            return false;
        }

        context.Users.Remove(user);
        await context.SaveChangesAsync();
        return true;
    }

    public async Task UpdateAsync(User user)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        // Attach only the root entity: users fetched from this repository have
        // ActiveWorkspace eagerly loaded, and Update() would mark that detached
        // workspace as Modified too, re-writing it with stale values.
        context.Entry(user).State = EntityState.Modified;
        await context.SaveChangesAsync();
    }

    public async Task UpdateActiveWorkspaceAsync(int userId, int workspaceId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        var user = await context.Users.FindAsync(userId);
        if (user != null)
        {
            user.ActiveWorkspaceId = workspaceId;
            await context.SaveChangesAsync();
        }
    }
}

