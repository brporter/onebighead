using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class TokenRevocationRepository : ITokenRevocationRepository
{
    private readonly AppDbContext _context;

    public TokenRevocationRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task<DateTime?> GetRevokedAtUtcAsync(int userId)
    {
        return await _context.TokenRevocations
            .AsNoTracking()
            .Where(r => r.UserId == userId)
            .Select(r => (DateTime?)r.RevokedAtUtc)
            .FirstOrDefaultAsync();
    }

    public async Task UpsertAsync(int userId, DateTime revokedAtUtc)
    {
        var existing = await _context.TokenRevocations
            .FirstOrDefaultAsync(r => r.UserId == userId);

        if (existing == null)
        {
            _context.TokenRevocations.Add(new TokenRevocation
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

        await _context.SaveChangesAsync();
    }
}
