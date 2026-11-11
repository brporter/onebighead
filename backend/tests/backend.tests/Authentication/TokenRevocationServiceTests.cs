using Moq;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;

namespace OneBigHead.Server.Tests.Authentication;

public class TokenRevocationServiceTests
{
    [Fact]
    public async Task Revoke_UsesAuthoritativeWriteAndHistoricalAuditPrecision()
    {
        var repository = new Mock<ITokenRevocationRepository>(MockBehavior.Strict);
        var time = new Mock<TimeProvider>();
        var now = new DateTimeOffset(2026, 11, 11, 12, 0, 0, 789, TimeSpan.Zero);
        time.Setup(clock => clock.GetUtcNow()).Returns(now);
        repository.Setup(repo => repo.UpsertAsync(7, now.UtcDateTime.AddMilliseconds(-789))).Returns(Task.CompletedTask);
        await new TokenRevocationService(repository.Object, time.Object).RevokeAsync(7);
        repository.VerifyAll();
        repository.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Revoke_PropagatesPersistenceFailure()
    {
        var repository = new Mock<ITokenRevocationRepository>();
        var failure = new InvalidOperationException("write failed");
        repository.Setup(repo => repo.UpsertAsync(7, It.IsAny<DateTime>())).ThrowsAsync(failure);
        Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TokenRevocationService(repository.Object, TimeProvider.System).RevokeAsync(7)));
    }
}
