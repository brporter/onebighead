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
    private DateTimeOffset _now = new(2026, 10, 5, 12, 0, 0, TimeSpan.Zero);
    private readonly Mock<TimeProvider> _timeProvider = new();

    public TokenRevocationServiceTests()
    {
        _mockRepository = new Mock<ITokenRevocationRepository>();
                var clock = new Mock<Microsoft.Extensions.Internal.ISystemClock>();
        clock.SetupGet(c => c.UtcNow).Returns(() => _now);
        _timeProvider.Setup(c => c.GetUtcNow()).Returns(() => _now);
        _cache = new MemoryCache(new MemoryCacheOptions { Clock = clock.Object });
    }

    private TokenRevocationService CreateService(int cacheTtlSeconds = 30)
    {
        var settings = new AuthenticationSettings
        {
            Jwt = new JwtSettings { RevocationCacheSeconds = cacheTtlSeconds }
        };

        return new TokenRevocationService(_mockRepository.Object, _cache, Options.Create(settings), _timeProvider.Object);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_NoRevocationEntry_ReturnsFalse()
    {
        _mockRepository.Setup(r => r.GetRevokedAtUtcAsync(TestUserId))
            .ReturnsAsync((DateTime?)null);
        var service = CreateService();

        var revoked = await service.IsTokenRevokedAsync(TestUserId, _now.UtcDateTime);

        Assert.False(revoked);
        _mockRepository.Verify(r => r.GetRevokedAtUtcAsync(TestUserId), Times.Once);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_TokenIssuedBeforeRevocation_ReturnsTrue()
    {
        var revokedAt = _now.UtcDateTime;
        _mockRepository.Setup(r => r.GetRevokedAtUtcAsync(TestUserId))
            .ReturnsAsync(revokedAt);
        var service = CreateService();

        var revoked = await service.IsTokenRevokedAsync(TestUserId, revokedAt.AddMinutes(-5));

        Assert.True(revoked);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_TokenIssuedAfterRevocation_ReturnsFalse()
    {
        var revokedAt = _now.UtcDateTime;
        _mockRepository.Setup(r => r.GetRevokedAtUtcAsync(TestUserId))
            .ReturnsAsync(revokedAt);
        var service = CreateService();

        var revoked = await service.IsTokenRevokedAsync(TestUserId, revokedAt.AddMinutes(5));

        Assert.False(revoked);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_TokenIssuedAtExactRevocationInstant_ReturnsFalse()
    {
        var revokedAt = _now.UtcDateTime;
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

        await service.IsTokenRevokedAsync(TestUserId, _now.UtcDateTime);
        await service.IsTokenRevokedAsync(TestUserId, _now.UtcDateTime);
        await service.IsTokenRevokedAsync(TestUserId, _now.UtcDateTime);

        _mockRepository.Verify(r => r.GetRevokedAtUtcAsync(TestUserId), Times.Once);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_CachesNegativeResultsPerUser()
    {
        _mockRepository.Setup(r => r.GetRevokedAtUtcAsync(It.IsAny<int>()))
            .ReturnsAsync((DateTime?)null);
        var service = CreateService();

        await service.IsTokenRevokedAsync(1, _now.UtcDateTime);
        await service.IsTokenRevokedAsync(2, _now.UtcDateTime);
        await service.IsTokenRevokedAsync(1, _now.UtcDateTime);
        await service.IsTokenRevokedAsync(2, _now.UtcDateTime);

        _mockRepository.Verify(r => r.GetRevokedAtUtcAsync(1), Times.Once);
        _mockRepository.Verify(r => r.GetRevokedAtUtcAsync(2), Times.Once);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_AfterTtlExpires_QueriesRepositoryAgain()
    {
        _mockRepository.Setup(r => r.GetRevokedAtUtcAsync(TestUserId))
            .ReturnsAsync((DateTime?)null);
        var service = CreateService(cacheTtlSeconds: 1);

        await service.IsTokenRevokedAsync(TestUserId, _now.UtcDateTime);
        _now = _now.AddSeconds(1.5);
        await service.IsTokenRevokedAsync(TestUserId, _now.UtcDateTime);

        _mockRepository.Verify(r => r.GetRevokedAtUtcAsync(TestUserId), Times.Exactly(2));
    }

    [Fact]
    public async Task RevokeAsync_PersistsFlooredTimestamp()
    {
        var service = CreateService();
        var before = _now.UtcDateTime;

        await service.RevokeAsync(TestUserId);

        var after = _now.UtcDateTime;
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
        var revoked = await service.IsTokenRevokedAsync(TestUserId, _now.UtcDateTime.AddMinutes(-5));

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
        Assert.False(await service.IsTokenRevokedAsync(TestUserId, _now.UtcDateTime.AddMinutes(-5)));

        await service.RevokeAsync(TestUserId);

        Assert.True(await service.IsTokenRevokedAsync(TestUserId, _now.UtcDateTime.AddMinutes(-5)));
    }
}
