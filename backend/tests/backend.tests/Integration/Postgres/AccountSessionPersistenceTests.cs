using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Administration;

namespace OneBigHead.Server.Tests.Integration.Postgres;

public partial class AccountSessionTests
{
    [Fact]
    public async Task Revocation_IsImmediateAcrossInstancesAndDoesNotDependOnClockOrder()
    {
        var first = new AccountSessionValidator(fixture.CreateContextFactory());
        var second = new AccountSessionValidator(fixture.CreateContextFactory());
        var users = new UserRepository(fixture.CreateContextFactory());
        var original = (await users.GetByIdAsync(1))!;
        var other = (await users.GetByIdAsync(2))!;
        Assert.True(await first.IsCurrentAsync(1, original.AuthenticationStamp));
        Assert.True(await second.IsCurrentAsync(1, original.AuthenticationStamp));
        var repository = new TokenRevocationRepository(fixture.CreateContextFactory());
        var time = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        foreach (var timestamp in new[] { time, time, time.AddDays(-1) })
        {
            var previous = (await users.GetByIdAsync(1))!;
            await repository.UpsertAsync(1, timestamp);
            Assert.False(await first.IsCurrentAsync(1, original.AuthenticationStamp));
            Assert.False(await second.IsCurrentAsync(1, previous.AuthenticationStamp));
            var current = (await users.GetByIdAsync(1))!;
            Assert.True(await second.IsCurrentAsync(1, current.AuthenticationStamp));
            Assert.True(await first.IsCurrentAsync(2, other.AuthenticationStamp));
            Assert.Equal(time, await repository.GetRevokedAtUtcAsync(1));
        }
    }

    [Fact]
    public async Task FailedRevocation_RollsBackStampAndAuditTogether()
    {
        await using var context = fixture.CreateContext();
        var original = (await context.Users.SingleAsync(user => user.Id == 1)).AuthenticationStamp;
        await context.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION session_failure() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'Session commit failure'; END $$
            """);
        await context.Database.ExecuteSqlRawAsync("""
            CREATE CONSTRAINT TRIGGER session_failure AFTER INSERT ON "TokenRevocations"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION session_failure()
            """);
        try
        {
            await Assert.ThrowsAsync<PostgresException>(() => new TokenRevocationRepository(fixture.CreateContextFactory())
                .UpsertAsync(1, DateTime.UtcNow));
            Assert.True(await new AccountSessionValidator(fixture.CreateContextFactory()).IsCurrentAsync(1, original));
            Assert.Empty(await context.TokenRevocations.ToListAsync());
        }
        finally
        {
            await context.Database.ExecuteSqlRawAsync("DROP TRIGGER session_failure ON \"TokenRevocations\"");
            await context.Database.ExecuteSqlRawAsync("DROP FUNCTION session_failure()");
        }
    }

    [Fact]
    public async Task StaleDetachedAccount_CannotOverwriteARevokedStampOrPrivileges()
    {
        var repository = new UserRepository(fixture.CreateContextFactory());
        var stale = (await repository.GetByIdAsync(1))!;
        await new TokenRevocationRepository(fixture.CreateContextFactory()).UpsertAsync(1, DateTime.UtcNow);
        stale.IsSystemAdministrator = true;
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => repository.UpdateAsync(stale));
        var current = (await repository.GetByIdAsync(1))!;
        Assert.False(current.IsSystemAdministrator);
        Assert.NotEqual(stale.AuthenticationStamp, current.AuthenticationStamp);
    }

    [Fact]
    public async Task DeletedOrMissingAccount_IsRejectedAndRestorationDoesNotReviveOldCookies()
    {
        var validator = new AccountSessionValidator(fixture.CreateContextFactory());
        Guid original;
        await using (var context = fixture.CreateContext())
        {
            var account = await context.Users.SingleAsync(user => user.Id == 1);
            original = account.AuthenticationStamp;
            account.IdentityProvider = IdentityProvider.Google;
            account.ProviderSubjectId = "existing-identity";
            account.IsDeleted = true;
            account.DeletedAt = DateTime.UtcNow;
            await context.SaveChangesAsync();
        }
        Assert.False(await validator.IsCurrentAsync(1, original));
        Assert.False(await validator.IsCurrentAsync(999, original));
        Assert.False(await validator.IsCurrentAsync(2, original));
        var restored = await new ExternalUserService(fixture.CreateContextFactory(), TimeProvider.System, NullLogger<ExternalUserService>.Instance)
            .GetOrCreateAsync(IdentityProvider.Google, new OidcValidationResult { IsValid = true, Subject = "existing-identity", Email = "owner@example.test" });
        Assert.NotNull(restored.User);
        Assert.False(await validator.IsCurrentAsync(1, original));
        Assert.True(await validator.IsCurrentAsync(1, restored.User.AuthenticationStamp));
        Assert.True(await new AdministratorUsers(fixture.CreateContextFactory()).DeleteAsync(1));
        Assert.False(await validator.IsCurrentAsync(1, restored.User.AuthenticationStamp));
    }

    [Fact]
    public async Task AdministratorChange_RevokesOldSnapshotButAnUnchangedRolePreservesIt()
    {
        var users = new UserRepository(fixture.CreateContextFactory());
        var command = new AdministratorUsers(fixture.CreateContextFactory());
        var first = (await users.GetByIdAsync(1))!;
        await command.SetAdministratorAsync(1, false);
        Assert.Equal(first.AuthenticationStamp, (await users.GetByIdAsync(1))!.AuthenticationStamp);
        await command.SetAdministratorAsync(1, true);
        var promoted = (await users.GetByIdAsync(1))!;
        Assert.NotEqual(first.AuthenticationStamp, promoted.AuthenticationStamp);
        await command.SetAdministratorAsync(1, false);
        Assert.NotEqual(promoted.AuthenticationStamp, (await users.GetByIdAsync(1))!.AuthenticationStamp);
    }

    [Fact]
    public async Task Stamp_IsPrivateAndGeneratedForDatabaseInserts()
    {
        await using var context = fixture.CreateContext();
        await context.Database.ExecuteSqlRawAsync("""
            INSERT INTO "Users" ("Id", "Email", "IdentityProvider", "IsSystemAdministrator", "IsDeleted", "CreatedAt")
            VALUES (3, 'raw@example.test', 0, false, false, CURRENT_TIMESTAMP)
            """);
        var accounts = await context.Users.OrderBy(user => user.Id).ToListAsync();
        Assert.Equal(3, accounts.Select(user => user.AuthenticationStamp).Distinct().Count());
        Assert.DoesNotContain(accounts, user => user.AuthenticationStamp == Guid.Empty);
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(accounts[0]));
        Assert.False(json.RootElement.TryGetProperty(nameof(User.AuthenticationStamp), out _));
    }

    [Fact]
    public async Task SessionLookup_PropagatesCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new AccountSessionValidator(fixture.CreateContextFactory())
            .IsCurrentAsync(1, Guid.NewGuid(), cancellation.Token));
    }
}
