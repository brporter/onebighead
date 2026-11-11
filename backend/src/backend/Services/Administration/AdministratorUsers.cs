using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Administration;

public sealed class AdministratorUsers(IDbContextFactory<AppDbContext> contextFactory) : IAdministratorUsers
{
    public async Task<bool> DeleteAsync(int id)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        var user = await context.Users.FindAsync(id);
        if (user is null) return false;
        context.Users.Remove(user);
        await context.SaveChangesAsync();
        return true;
    }

    public async Task<UserSummaryResponse?> SetAdministratorAsync(int id, bool enabled)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        var user = await context.Users.Include(user => user.ActiveWorkspace).SingleOrDefaultAsync(user => user.Id == id);
        if (user is null) return null;
        if (user.IsSystemAdministrator != enabled) user.AuthenticationStamp = Guid.NewGuid();
        user.IsSystemAdministrator = enabled;
        await context.SaveChangesAsync();
        return UserSummaryResponse.FromUser(user);
    }
}
