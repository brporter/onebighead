using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Accounts;

public sealed class AccountDeletionReader(IDbContextFactory<AppDbContext> contextFactory) : IAccountDeletionReader
{
    public async Task<UserDeletionInfoResponse?> ReadAsync(int userId)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        var user = await AccountDeletionSnapshot.LoadAsync(context, userId);
        return user is null ? null : AccountDeletionPolicy.Describe(user);
    }
}
