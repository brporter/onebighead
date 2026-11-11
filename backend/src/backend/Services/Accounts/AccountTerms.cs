using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;

namespace OneBigHead.Server.Services.Accounts;

public sealed class AccountTerms(IDbContextFactory<AppDbContext> contexts, TimeProvider time) : IAccountTerms
{
    public async Task<DateTime?> AcceptAsync(int userId, CancellationToken cancellationToken)
    {
        await using var context = await contexts.CreateDbContextAsync(cancellationToken);
        var acceptedAt = time.GetUtcNow().UtcDateTime;
        // One conditional statement updates only consent. It cannot restore an account or
        // overwrite identity, membership selection or privileges from an earlier read.
        var updated = await context.Users.Where(user => user.Id == userId && !user.IsDeleted)
            .ExecuteUpdateAsync(update => update.SetProperty(user => user.AcceptedTermsAt, acceptedAt), cancellationToken);
        return updated == 0 ? null : acceptedAt;
    }
}
