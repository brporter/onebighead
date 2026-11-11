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

    public async Task<User?> GetByIdAsync(int id)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.Users
            .Include(u => u.ActiveWorkspace)
            .FirstOrDefaultAsync(u => u.Id == id);
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

    public async Task UpdateAsync(User user)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        // Attach only the root entity: users fetched from this repository have
        // ActiveWorkspace eagerly loaded, and Update() would mark that detached
        // workspace as Modified too, re-writing it with stale values.
        context.Entry(user).State = EntityState.Modified;
        await context.SaveChangesAsync();
    }

}
