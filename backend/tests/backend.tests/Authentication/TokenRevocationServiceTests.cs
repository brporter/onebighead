using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Moq;

namespace OneBigHead.Server.Tests.Authentication;

[Trait("Category", "Unit")]
public class TokenRevocationServiceTests
{
    private const int TestUserId = 42;

    private readonly Mock<ITokenRevocationRepository> _mockRepository;
    private readonly MemoryCache _cache;

    public TokenRevocationServiceTests()
    {
        _mockRepository = new Mock<ITokenRevocationRepository>();
        _cache = new MemoryCache(new MemoryCacheOptions());
    }

    private TokenRevocationService CreateService(int cacheTtlSeconds = 30)
    {
        var settings = new AuthenticationSettings
        {
            Jwt = new JwtSettings { RevocationCacheSeconds = cacheTtlSeconds }
        };

        return new TokenRevocationService(_mockRepository.Object, _cache, Options.Create(settings));
    }

    [Fact]
    public async Task IsTokenRevokedAsync_NoRevocationEntry_ReturnsFalse()
    {
        _mockRepository.Setup(r => r.GetRevokedAtUtcAsync(TestUserId))
            .ReturnsAsync((DateTime?)null);
        var service = CreateService();

        var revoked = await service.IsTokenRevokedAsync(TestUserId, DateTime.UtcNow);

        Assert.False(revoked);
        _mockRepository.Verify(r => r.GetRevokedAtUtcAsync(TestUserId), Times.Once);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_TokenIssuedBeforeRevocation_ReturnsTrue()
    {
        var revokedAt = DateTime.UtcNow;
        _mockRepository.Setup(r => r.GetRevokedAtUtcAsync(TestUserId))
            .ReturnsAsync(revokedAt);
        var service = CreateService();

        var revoked = await service.IsTokenRevokedAsync(TestUserId, revokedAt.AddMinutes(-5));

        Assert.True(revoked);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_TokenIssuedAfterRevocation_ReturnsFalse()
    {
        var revokedAt = DateTime.UtcNow;
        _mockRepository.Setup(r => r.GetRevokedAtUtcAsync(TestUserId))
            .ReturnsAsync(revokedAt);
        var service = CreateService();

        var revoked = await service.IsTokenRevokedAsync(TestUserId, revokedAt.AddMinutes(5));

        Assert.False(revoked);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_TokenIssuedAtExactRevocationInstant_ReturnsFalse()
    {
        var revokedAt = DateTime.UtcNow;
        _mockRepository.Setup(r => r.GetRevokedAtUtcAsync(TestUserId))
            .ReturnsAsync(revokedAt);
        var service = CreateService();

        var revoked = await service.IsTokenRevokedAsync(TestUserId, revokedAt);

        Assert.False(revoked);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_WithinTtl_UsesCachedResult()
    {
        _mockRepository.Setup(r => r.GetRevokedAtUtcAsync(TestUserId))
            .ReturnsAsync((DateTime?)null);
        var service = CreateService();

        await service.IsTokenRevokedAsync(TestUserId, DateTime.UtcNow);
        await service.IsTokenRevokedAsync(TestUserId, DateTime.UtcNow);
        await service.IsTokenRevokedAsync(TestUserId, DateTime.UtcNow);

        _mockRepository.Verify(r => r.GetRevokedAtUtcAsync(TestUserId), Times.Once);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_CachesNegativeResultsPerUser()
    {
        _mockRepository.Setup(r => r.GetRevokedAtUtcAsync(It.IsAny<int>()))
            .ReturnsAsync((DateTime?)null);
        var service = CreateService();

        await service.IsTokenRevokedAsync(1, DateTime.UtcNow);
        await service.IsTokenRevokedAsync(2, DateTime.UtcNow);
        await service.IsTokenRevokedAsync(1, DateTime.UtcNow);
        await service.IsTokenRevokedAsync(2, DateTime.UtcNow);

        _mockRepository.Verify(r => r.GetRevokedAtUtcAsync(1), Times.Once);
        _mockRepository.Verify(r => r.GetRevokedAtUtcAsync(2), Times.Once);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_AfterTtlExpires_QueriesRepositoryAgain()
    {
        _mockRepository.Setup(r => r.GetRevokedAtUtcAsync(TestUserId))
            .ReturnsAsync((DateTime?)null);
        var service = CreateService(cacheTtlSeconds: 1);

        await service.IsTokenRevokedAsync(TestUserId, DateTime.UtcNow);
        await Task.Delay(TimeSpan.FromSeconds(1.5));
        await service.IsTokenRevokedAsync(TestUserId, DateTime.UtcNow);

        _mockRepository.Verify(r => r.GetRevokedAtUtcAsync(TestUserId), Times.Exactly(2));
    }

    [Fact]
    public async Task RevokeAsync_PersistsFlooredTimestamp()
    {
        var service = CreateService();
        var before = DateTime.UtcNow;

        await service.RevokeAsync(TestUserId);

        var after = DateTime.UtcNow;
        _mockRepository.Verify(r => r.UpsertAsync(TestUserId, It.Is<DateTime>(t =>
            t.Ticks % TimeSpan.TicksPerSecond == 0 &&
            t >= before.AddSeconds(-1) &&
            t <= after &&
            t.Kind == DateTimeKind.Utc)), Times.Once);
    }

    [Fact]
    public async Task RevokeAsync_TakesEffectImmediatelyWithoutRepositoryLookup()
    {
        var service = CreateService();

        await service.RevokeAsync(TestUserId);
        var revoked = await service.IsTokenRevokedAsync(TestUserId, DateTime.UtcNow.AddMinutes(-5));

        Assert.True(revoked);
        // The cache was primed by RevokeAsync, so no read-side lookup occurred
        _mockRepository.Verify(r => r.GetRevokedAtUtcAsync(It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task RevokeAsync_OverwritesStaleCachedNegativeResult()
    {
        _mockRepository.Setup(r => r.GetRevokedAtUtcAsync(TestUserId))
            .ReturnsAsync((DateTime?)null);
        var service = CreateService();

        // Prime the cache with "not revoked"
        Assert.False(await service.IsTokenRevokedAsync(TestUserId, DateTime.UtcNow.AddMinutes(-5)));

        await service.RevokeAsync(TestUserId);

        Assert.True(await service.IsTokenRevokedAsync(TestUserId, DateTime.UtcNow.AddMinutes(-5)));
    }
}
