using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Npgsql;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Accounts;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class AccountTermsTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 12, 0, 0, TimeSpan.Zero);

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var db = fixture.CreateContext();
        db.Workspaces.AddRange(new Workspace { Id = 1, Name = "Original" }, new Workspace { Id = 2, Name = "Current" });
        db.Users.AddRange(new User { Id = 1, Email = "original@example.test", ActiveWorkspaceId = 1 },
            new User { Id = 2, Email = "without-workspace@example.test" },
            new User { Id = 3, Email = "deleted@example.test", IsDeleted = true, DeletedAt = Now.AddDays(-1).UtcDateTime });
        await db.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task Accept_RecordsConsentForActiveAndWorkspaceLessAccounts(int userId)
    {
        var terms = new AccountTerms(fixture.CreateContextFactory(), new Clock());
        Assert.Equal(Now.UtcDateTime, await terms.AcceptAsync(userId, CancellationToken.None));
        await using var db = fixture.CreateContext();
        var user = await db.Users.SingleAsync(u => u.Id == userId);
        Assert.Equal(Now.UtcDateTime, user.AcceptedTermsAt);
        Assert.True(user.HasAcceptedTerms);
        Assert.False(user.IsDeleted);
        Assert.Equal(userId == 1 ? 1 : (int?)null, user.ActiveWorkspaceId);
        Assert.All(await db.Users.Where(u => u.Id != userId).ToListAsync(), u => Assert.Null(u.AcceptedTermsAt));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(999)]
    public async Task MissingOrDeletedAccount_DoesNotRecordConsent(int userId)
    {
        Assert.Null(await new AccountTerms(fixture.CreateContextFactory(), new Clock()).AcceptAsync(userId, CancellationToken.None));
        await using var db = fixture.CreateContext();
        Assert.All(await db.Users.ToListAsync(), u => Assert.Null(u.AcceptedTermsAt));
        Assert.True((await db.Users.SingleAsync(u => u.Id == 3)).IsDeleted);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AccountChangesImmediatelyBeforeWrite_ArePreserved(bool deleteAccount)
    {
        var before = new BeforeUpdate(async _ =>
        {
            await using var db = fixture.CreateContext();
            var user = await db.Users.SingleAsync(u => u.Id == 1);
            user.ActiveWorkspaceId = 2;
            user.Email = "current@example.test";
            user.IdentityProvider = IdentityProvider.Google;
            user.ProviderSubjectId = "current-identity";
            user.IsSystemAdministrator = true;
            user.IsDeleted = deleteAccount;
            user.DeletedAt = deleteAccount ? Now.UtcDateTime : null;
            await db.SaveChangesAsync();
        });
        var result = await Terms(before).AcceptAsync(1, CancellationToken.None);
        Assert.Equal(deleteAccount ? null : (DateTime?)Now.UtcDateTime, result);
        await using var check = fixture.CreateContext();
        var stored = await check.Users.SingleAsync(u => u.Id == 1);
        Assert.Equal(2, stored.ActiveWorkspaceId);
        Assert.Equal("current@example.test", stored.Email);
        Assert.Equal(IdentityProvider.Google, stored.IdentityProvider);
        Assert.Equal("current-identity", stored.ProviderSubjectId);
        Assert.True(stored.IsSystemAdministrator);
        Assert.Equal(deleteAccount, stored.IsDeleted);
        Assert.Equal(deleteAccount ? Now.UtcDateTime : (DateTime?)null, stored.DeletedAt);
        Assert.Equal(result, stored.AcceptedTermsAt);
    }

    [Fact]
    public async Task CancellationBeforeStatement_AbortsWithoutRecordingConsent()
    {
        using var cancellation = new CancellationTokenSource();
        var before = new BeforeUpdate(token =>
        {
            Assert.Equal(cancellation.Token, token);
            cancellation.Cancel();
            token.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Terms(before).AcceptAsync(1, cancellation.Token));
        await using var db = fixture.CreateContext();
        Assert.Null((await db.Users.SingleAsync(u => u.Id == 1)).AcceptedTermsAt);
    }

    [Fact]
    public async Task DatabaseFailure_PropagatesWithoutRecordingConsent()
    {
        await using var db = fixture.CreateContext();
        await db.Database.ExecuteSqlRawAsync("""ALTER TABLE "Users" ADD CONSTRAINT reject_test_consent CHECK ("AcceptedTermsAt" IS NULL)""");
        try
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() =>
                new AccountTerms(fixture.CreateContextFactory(), new Clock()).AcceptAsync(1, CancellationToken.None));
            Assert.Equal(PostgresErrorCodes.CheckViolation, error.SqlState);
            Assert.Null((await db.Users.SingleAsync(u => u.Id == 1)).AcceptedTermsAt);
        }
        finally
        {
            await db.Database.ExecuteSqlRawAsync("""ALTER TABLE "Users" DROP CONSTRAINT reject_test_consent""");
        }
    }

    [Theory]
    [InlineData("1", HttpStatusCode.OK)]
    [InlineData("2", HttpStatusCode.OK)]
    [InlineData("3", HttpStatusCode.NotFound)]
    [InlineData("999", HttpStatusCode.NotFound)]
    [InlineData(null, HttpStatusCode.Unauthorized)]
    public async Task HttpEndpoint_UsesRegisteredCommandAndPreservesResponseContract(string? userId, HttpStatusCode expected)
    {
        await using var app = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var client = app.CreateClient();
        if (userId is not null)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, userId);
            client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, "0");
        }
        var before = DateTime.UtcNow;
        using var response = await client.PostAsync("/api/auth/accept-terms", null);
        Assert.Equal(expected, response.StatusCode);
        Assert.False(response.Headers.Contains("Set-Cookie"));
        await using var db = fixture.CreateContext();
        if (expected == HttpStatusCode.OK)
        {
            var consent = await response.Content.ReadFromJsonAsync<AcceptTermsResponse>();
            Assert.NotNull(consent);
            Assert.True(consent.HasAcceptedTerms);
            Assert.InRange(consent.AcceptedTermsAt, before, DateTime.UtcNow);
            var stored = (await db.Users.SingleAsync(u => u.Id == int.Parse(userId!))).AcceptedTermsAt;
            // PostgreSQL timestamps retain microseconds; JSON preserves .NET's finer precision.
            Assert.InRange((consent.AcceptedTermsAt - stored!.Value).Ticks, 0, 9);
        }
        else
        {
            Assert.All(await db.Users.ToListAsync(), u => Assert.Null(u.AcceptedTermsAt));
        }
    }

    private AccountTerms Terms(DbCommandInterceptor interceptor) => new(new TestDbContextFactory(
        new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString).AddInterceptors(interceptor).Options), new Clock());

    private sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }

    private sealed class BeforeUpdate(Func<CancellationToken, Task> before) : DbCommandInterceptor
    {
        public override async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            await before(cancellationToken);
            return result;
        }
    }
}
