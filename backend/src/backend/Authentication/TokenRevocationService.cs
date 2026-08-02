using OneBigHead.Server.Data;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace OneBigHead.Server.Authentication;

public class TokenRevocationService : ITokenRevocationService
{
    private readonly ITokenRevocationRepository _repository;
    private readonly IMemoryCache _cache;
    private readonly TimeSpan _cacheTtl;

    public TokenRevocationService(
        ITokenRevocationRepository repository,
        IMemoryCache cache,
        IOptions<AuthenticationSettings> settings)
    {
        _repository = repository;
        _cache = cache;
        _cacheTtl = TimeSpan.FromSeconds(settings.Value.Jwt.RevocationCacheSeconds);
    }

    public async Task RevokeAsync(int userId)
    {
        // Floor to whole seconds to match the granularity of the JWT "iat" claim.
        // A token minted in the same second as the revocation (i.e., the re-login
        // that follows it) compares as not-revoked.
        var revokedAt = FloorToSeconds(DateTime.UtcNow);

        await _repository.UpsertAsync(userId, revokedAt);

        // Update the cache immediately so this instance enforces the revocation
        // without waiting for the TTL to lapse.
        _cache.Set(CacheKey(userId), (DateTime?)revokedAt, _cacheTtl);
    }

    public async Task<bool> IsTokenRevokedAsync(int userId, DateTime issuedAtUtc)
    {
        var key = CacheKey(userId);

        if (!_cache.TryGetValue(key, out DateTime? revokedAt))
        {
            revokedAt = await _repository.GetRevokedAtUtcAsync(userId);
            _cache.Set(key, revokedAt, _cacheTtl);
        }

        return revokedAt.HasValue && issuedAtUtc < revokedAt.Value;
    }

    private static string CacheKey(int userId) => $"token-revocation:{userId}";

    private static DateTime FloorToSeconds(DateTime value) =>
        new(value.Ticks - (value.Ticks % TimeSpan.TicksPerSecond), value.Kind);
}
