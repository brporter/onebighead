using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Accounts;

internal static class AccountDeletionSnapshot
{
    // One database statement gives preview and command the same complete graph.
    // The command owns the transaction; this loader never saves or commits.
    public static Task<User?> LoadAsync(AppDbContext context, int userId) => context.Users
        .Include(u => u.WorkspaceMemberships)
        .ThenInclude(m => m.Workspace)
        .ThenInclude(w => w.WorkspaceUsers)
        .ThenInclude(m => m.User)
        .AsSingleQuery()
        .SingleOrDefaultAsync(u => u.Id == userId);
}
