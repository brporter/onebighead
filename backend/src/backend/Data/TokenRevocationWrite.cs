using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Data;

/// <summary>Uses the caller's transaction and never moves an existing revocation backwards.</summary>
internal static class TokenRevocationWrite
{
    public static async Task UpsertAsync(AppDbContext context, int userId, DateTime revokedAtUtc, CancellationToken cancellationToken = default)
    {
        var stamp = Guid.NewGuid();
        await context.Users.Where(user => user.Id == userId)
            .ExecuteUpdateAsync(update => update.SetProperty(user => user.AuthenticationStamp, stamp), cancellationToken);
        // Commands may return this tracked account to issue a replacement cookie.
        // Keep its snapshot and concurrency original aligned with our database write.
        foreach (var entry in context.ChangeTracker.Entries<User>().Where(entry => entry.Entity.Id == userId).ToList())
        {
            var property = entry.Property(user => user.AuthenticationStamp);
            property.CurrentValue = stamp;
            property.OriginalValue = stamp;
            property.IsModified = false;
        }
        await context.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO "TokenRevocations" ("UserId", "RevokedAtUtc")
            VALUES ({userId}, {revokedAtUtc})
            ON CONFLICT ("UserId") DO UPDATE
            SET "RevokedAtUtc" = GREATEST("TokenRevocations"."RevokedAtUtc", EXCLUDED."RevokedAtUtc")
            """, cancellationToken);
    }
}
