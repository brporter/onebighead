using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;

namespace OneBigHead.Server.Authentication;

public sealed class CurrentUserSessionReader(IDbContextFactory<AppDbContext> contextFactory) : ICurrentUserSessionReader
{
    public async Task<CurrentUserSession?> ReadAsync(int userId)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        var user = await context.Users.AsNoTracking()
            .Include(u => u.WorkspaceMemberships).ThenInclude(m => m.Workspace)
            .SingleOrDefaultAsync(u => u.Id == userId);
        if (user is null) return null;
        return CurrentUserSession.FromUser(user);
    }
}
