using OneBigHead.Server.Models;
using OneBigHead.Server.Tests.Integration.Postgres;
using OneBigHead.Server.Data;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Tests.Integration.Data;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class TokenRevocationRepositoryTests : IAsyncLifetime
{
    private readonly AppDbContext _context;
    private readonly TokenRevocationRepository _repository;

    private readonly PostgresIntegrationFixture _fixture;

    public TokenRevocationRepositoryTests(PostgresIntegrationFixture fixture)
    {
        _fixture = fixture;
        _context = fixture.CreateContext();
        _repository = new TokenRevocationRepository(fixture.CreateContextFactory());
    }

    public async Task InitializeAsync()
    {
        await _fixture.ResetAsync();
        _context.Workspaces.Add(new Workspace { Id = 1, Name = "Workspace" });
        _context.Users.AddRange(new User { Id = 1, Email = "one@example.com", ActiveWorkspaceId = 1 },
            new User { Id = 2, Email = "two@example.com", ActiveWorkspaceId = 1 });
        await _context.SaveChangesAsync();
    }

    public Task DisposeAsync() => _context.DisposeAsync().AsTask();


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
