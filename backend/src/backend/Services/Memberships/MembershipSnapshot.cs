using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Memberships;

internal static class MembershipSnapshot
{
    public static Task<User?> LoadActiveUserAsync(AppDbContext context, int userId) => context.Users
        .Include(u => u.WorkspaceMemberships).ThenInclude(m => m.Workspace)
        .AsSingleQuery().SingleOrDefaultAsync(u => u.Id == userId && !u.IsDeleted);
}
