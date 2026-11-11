using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;

namespace OneBigHead.Server.Services.Administration;

/** Administrator privileges are checked against the current account on each request. */
public sealed class AdministratorAccessService(IDbContextFactory<AppDbContext> contextFactory) : IAdministratorAccessService
{
    public async Task<bool> HasAccessAsync(int userId)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        var user = await context.Users.AsNoTracking().SingleOrDefaultAsync(user => user.Id == userId);
        return AdministratorAccessPolicy.IsAllowed(user);
    }
}
