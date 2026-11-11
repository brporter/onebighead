using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;

namespace OneBigHead.Server.Authentication;

public sealed class AccountSessionValidator(IDbContextFactory<AppDbContext> contexts) : IAccountSessionValidator
{
    public async Task<bool> IsCurrentAsync(int userId, Guid authenticationStamp, CancellationToken cancellationToken = default)
    {
        // A fresh primary-key lookup deliberately avoids cross-instance cache delays.
        await using var context = await contexts.CreateDbContextAsync(cancellationToken);
        return await context.Users.AnyAsync(user => user.Id == userId && !user.IsDeleted &&
            user.AuthenticationStamp == authenticationStamp, cancellationToken);
    }
}
