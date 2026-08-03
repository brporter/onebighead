using OneBigHead.Server.Models;
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
        var existing = await context.TokenRevocations
            .FirstOrDefaultAsync(r => r.UserId == userId);

        if (existing == null)
        {
            context.TokenRevocations.Add(new TokenRevocation
            {
                UserId = userId,
                RevokedAtUtc = revokedAtUtc
            });
        }
        else if (revokedAtUtc > existing.RevokedAtUtc)
        {
            existing.RevokedAtUtc = revokedAtUtc;
        }
        else
        {
            return;
        }

        await context.SaveChangesAsync();
    }
}
