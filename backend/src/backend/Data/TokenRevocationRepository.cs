using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class TokenRevocationRepository : ITokenRevocationRepository
{
    private readonly IDbContextFactory<AppDbContext> _contextFactory;

    public TokenRevocationRepository(IDbContextFactory<AppDbContext> contextFactory)
    {
        _contextFactory = contextFactory;
    }

    public async Task<DateTime?> GetRevokedAtUtcAsync(int userId)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.TokenRevocations
            .AsNoTracking()
            .Where(r => r.UserId == userId)
            .Select(r => (DateTime?)r.RevokedAtUtc)
            .FirstOrDefaultAsync();
    }

    public async Task UpsertAsync(int userId, DateTime revokedAtUtc)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        await context.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO "TokenRevocations" ("UserId", "RevokedAtUtc")
            VALUES ({userId}, {revokedAtUtc})
            ON CONFLICT ("UserId") DO UPDATE
            SET "RevokedAtUtc" = GREATEST("TokenRevocations"."RevokedAtUtc", EXCLUDED."RevokedAtUtc")
            """);
    }
}
