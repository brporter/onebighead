using OneBigHead.Server.Data;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Tests.Integration.Data;

[Trait("Category", "Integration")]
public class TokenRevocationRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly TokenRevocationRepository _repository;

    public TokenRevocationRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _repository = new TokenRevocationRepository(new TestDbContextFactory(options));
    }

    public void Dispose()
    {
        _context.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task GetRevokedAtUtcAsync_NoEntry_ReturnsNull()
    {
        var result = await _repository.GetRevokedAtUtcAsync(1);

        Assert.Null(result);
    }

    [Fact]
    public async Task UpsertAsync_NewUser_CreatesEntry()
    {
        var revokedAt = new DateTime(2026, 8, 1, 12, 0, 0, DateTimeKind.Utc);

        await _repository.UpsertAsync(1, revokedAt);

        Assert.Equal(revokedAt, await _repository.GetRevokedAtUtcAsync(1));
    }

    [Fact]
    public async Task UpsertAsync_LaterTimestamp_AdvancesExistingEntry()
    {
        var first = new DateTime(2026, 8, 1, 12, 0, 0, DateTimeKind.Utc);
        var second = first.AddHours(1);

        await _repository.UpsertAsync(1, first);
        await _repository.UpsertAsync(1, second);

        Assert.Equal(second, await _repository.GetRevokedAtUtcAsync(1));
        Assert.Equal(1, await _context.TokenRevocations.CountAsync());
    }

    [Fact]
    public async Task UpsertAsync_EarlierTimestamp_DoesNotRegressExistingEntry()
    {
        var first = new DateTime(2026, 8, 1, 12, 0, 0, DateTimeKind.Utc);
        var earlier = first.AddHours(-1);

        await _repository.UpsertAsync(1, first);
        await _repository.UpsertAsync(1, earlier);

        Assert.Equal(first, await _repository.GetRevokedAtUtcAsync(1));
    }

    [Fact]
    public async Task UpsertAsync_DifferentUsers_KeepsIndependentEntries()
    {
        var timestampA = new DateTime(2026, 8, 1, 12, 0, 0, DateTimeKind.Utc);
        var timestampB = timestampA.AddMinutes(30);

        await _repository.UpsertAsync(1, timestampA);
        await _repository.UpsertAsync(2, timestampB);

        Assert.Equal(timestampA, await _repository.GetRevokedAtUtcAsync(1));
        Assert.Equal(timestampB, await _repository.GetRevokedAtUtcAsync(2));
    }
}
