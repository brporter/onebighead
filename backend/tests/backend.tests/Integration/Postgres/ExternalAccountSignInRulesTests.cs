using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Npgsql;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration.Postgres;

public partial class ExternalAccountSignInTests
{
    [Theory]
    [InlineData(false, "admin")]
    [InlineData(true, "admin")]
    [InlineData(false, "normal")]
    [InlineData(true, "missing")]
    [InlineData(true, "workspace-less")]
    public async Task OriginalIdentity_PreservesAccountFieldsAndUsesTheCurrentMembership(bool deleted, string membership)
    {
        await SeedAccount(IdentityProvider.Google, "original", deleted);
        await using (var context = fixture.CreateContext())
        {
            if (membership == "normal") await context.WorkspaceUsers.ExecuteUpdateAsync(set => set.SetProperty(member => member.WorkspaceRole, WorkspaceRole.Normal));
            if (membership == "missing") await context.WorkspaceUsers.ExecuteDeleteAsync();
            if (membership == "workspace-less") await context.Users.ExecuteUpdateAsync(set => set.SetProperty(user => user.ActiveWorkspaceId, (int?)null));
        }

        var result = await Service().GetOrCreateAsync(IdentityProvider.Google, Identity(email: "changed@example.test"));
        Assert.NotNull(result.User);
        Assert.Null(result.Error);
        Assert.Equal(1, result.User.Id);
        Assert.Equal("owner@example.test", result.User.Email);
        Assert.Equal("original", result.User.ProviderSubjectId);
        Assert.True(result.User.IsSystemAdministrator);
        Assert.Equal(new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc), result.User.AcceptedTermsAt);
        Assert.False(result.User.IsDeleted);
        Assert.Null(result.User.DeletedAt);
        Assert.Equal(membership == "admin" ? WorkspaceRole.WorkspaceAdmin : WorkspaceRole.Normal, result.WorkspaceRole);
        await using var check = fixture.CreateContext();
        Assert.False((await check.Users.SingleAsync()).IsDeleted);
        Assert.Single(await check.Workspaces.ToListAsync());
    }

    [Fact]
    public async Task NewIdentity_CreatesOneAccountWorkspaceAndAdminMembershipWithTheSameTimestamp()
    {
        var now = new DateTimeOffset(2026, 1, 15, 12, 0, 0, TimeSpan.Zero);
        var service = new ExternalUserService(fixture.CreateContextFactory(), new SignInClock(now), NullLogger<ExternalUserService>.Instance);
        var result = await service.GetOrCreateAsync(IdentityProvider.Google, Identity("new", " OWNER@Example.Test "));
        Assert.NotNull(result.User);
        Assert.Equal("OWNER@Example.Test", result.User.Email);
        Assert.Equal("Example.Test", result.User.ActiveWorkspace!.Name);
        Assert.Equal(now.UtcDateTime, result.User.CreatedAt);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, result.WorkspaceRole);
        Assert.False(result.User.IsSystemAdministrator);
        Assert.Null(result.User.AcceptedTermsAt);
        await using var check = fixture.CreateContext();
        Assert.Equal(now.UtcDateTime, (await check.Workspaces.SingleAsync()).CreatedAt);
        var membership = await check.WorkspaceUsers.SingleAsync();
        Assert.Equal(now.UtcDateTime, membership.CreatedAt);
        Assert.Equal(result.User.Id, membership.UserId);
        Assert.Equal(result.User.ActiveWorkspaceId, membership.WorkspaceId);
        Assert.Empty(await check.Collections.ToListAsync());
        var again = await service.GetOrCreateAsync(IdentityProvider.Google, Identity("new", "owner@example.test"));
        Assert.Equal(result.User.Id, again.User!.Id);
        Assert.Single(await check.Users.ToListAsync());
        Assert.Single(await check.Workspaces.ToListAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PendingEmail_DoesNotAuthorizeOrRestoreThePendingAccount(bool deleted)
    {
        await SeedAccount(IdentityProvider.None, null, deleted);
        var result = await Service().GetOrCreateAsync(IdentityProvider.Google, Identity("linked", " OWNER@EXAMPLE.TEST "));
        Assert.NotNull(result.User);
        Assert.NotEqual(1, result.User.Id);
        await using var check = fixture.CreateContext();
        var pending = await check.Users.SingleAsync(user => user.Id == 1);
        Assert.Equal(IdentityProvider.None, pending.IdentityProvider);
        Assert.Null(pending.ProviderSubjectId);
        Assert.Equal(deleted, pending.IsDeleted);
        Assert.Equal(2, await check.WorkspaceUsers.CountAsync());
    }

    [Fact]
    public async Task AmbiguousEmail_DoesNotPreventIndependentIdentitiesFromSigningIn()
    {
        await SeedAccount(IdentityProvider.Google, "original");
        await using (var context = fixture.CreateContext())
        {
            context.Users.Add(new User { Email = "OWNER@EXAMPLE.TEST", IdentityProvider = IdentityProvider.Microsoft, ProviderSubjectId = "second" });
            await context.SaveChangesAsync();
        }
        var created = await Service().GetOrCreateAsync(IdentityProvider.Apple, Identity("third"));
        Assert.NotNull(created.User);
        Assert.NotEqual(1, created.User.Id);
        Assert.Equal(1, (await Service().GetOrCreateAsync(IdentityProvider.Google, Identity())).User!.Id);
        await using var check = fixture.CreateContext();
        Assert.Equal(3, await check.Users.CountAsync());
        Assert.Equal(2, await check.Workspaces.CountAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConcurrentProvisioning_DoesNotLeaveDuplicateIdentitiesOrOrphanWorkspaces(bool sameIdentity)
    {
        var synchronize = new SynchronizedSaves();
        var results = await Task.WhenAll(
            Service(synchronize).GetOrCreateAsync(IdentityProvider.Google, Identity()),
            Service(synchronize).GetOrCreateAsync(sameIdentity ? IdentityProvider.Google : IdentityProvider.Microsoft, Identity()));
        Assert.Contains(results, result => result.User is not null);
        await using var check = fixture.CreateContext();
        var count = results.Count(result => result.User is not null);
        Assert.Equal(count, await check.Users.CountAsync());
        Assert.Equal(count, await check.Workspaces.CountAsync());
        Assert.Equal(count, await check.WorkspaceUsers.CountAsync());
        var google = await Service().GetOrCreateAsync(IdentityProvider.Google, Identity());
        var other = await Service().GetOrCreateAsync(sameIdentity ? IdentityProvider.Google : IdentityProvider.Microsoft, Identity());
        Assert.Equal(sameIdentity, google.User!.Id == other.User!.Id);
        Assert.Equal(sameIdentity ? 1 : 2, await check.Users.CountAsync());
    }

    [Theory]
    [InlineData("40001", null, true)]
    [InlineData("23505", "IX_Users_IdentityProvider_ProviderSubjectId", true)]
    [InlineData("23505", "unrelated_constraint", false)]
    [InlineData("23514", null, false)]
    [InlineData("storage", null, false)]
    [InlineData("cancelled", null, false)]
    public async Task FailureAfterSaving_RollsBackTheWholeAccountGraph(string code, string? constraint, bool conflict)
    {
        Exception failure = code switch
        {
            "storage" => new InvalidOperationException("Storage unavailable"),
            "cancelled" => new OperationCanceledException(),
            _ => new DbUpdateException("Write failed", new PostgresException("Injected failure", "ERROR", "ERROR", code, constraintName: constraint))
        };
        ExternalSignInResult? result = null;
        var thrown = await Record.ExceptionAsync(async () => result = await Service(new AfterSignInSave(failure))
            .GetOrCreateAsync(IdentityProvider.Google, Identity()));
        if (conflict)
        {
            Assert.Null(thrown);
            Assert.Null(result!.User);
            Assert.Equal("Account sign-in changed. Please try again.", result.Error);
        }
        else Assert.Same(failure, thrown);
        await AssertNoProvisioning();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancelledSignIn_DoesNotLeaveACreatedAccount(bool afterSaving)
    {
        using var cancellation = new CancellationTokenSource();
        if (!afterSaving) cancellation.Cancel();
        var service = afterSaving ? Service(new CancelAfterSignInSave(cancellation)) : Service();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.GetOrCreateAsync(IdentityProvider.Google, Identity(), cancellation.Token));
        await AssertNoProvisioning();
    }

    [Fact]
    public async Task FailedPendingLink_RollsBackBothRestorationAndIdentityAssignment()
    {
        await SeedAccount(IdentityProvider.None, null, deleted: true);
        var failure = new InvalidOperationException("Persistence unavailable");
        Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Service(new AfterSignInSave(failure)).GetOrCreateAsync(IdentityProvider.Google, Identity("new"))));
        await using var check = fixture.CreateContext();
        var user = await check.Users.SingleAsync();
        Assert.True(user.IsDeleted);
        Assert.NotNull(user.DeletedAt);
        Assert.Equal(IdentityProvider.None, user.IdentityProvider);
        Assert.Null(user.ProviderSubjectId);
        Assert.Single(await check.WorkspaceUsers.ToListAsync());
    }

    [Fact]
    public async Task CommitFailure_RollsBackAllProvisioning()
    {
        await using var setup = fixture.CreateContext();
        await setup.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION reject_sign_in_commit() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'commit rejected' USING ERRCODE = '23514'; END $$;
            CREATE CONSTRAINT TRIGGER reject_sign_in_commit AFTER INSERT ON "WorkspaceUsers"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_sign_in_commit();
            """);
        try
        {
            await Assert.ThrowsAsync<PostgresException>(() => Service().GetOrCreateAsync(IdentityProvider.Google, Identity()));
            await AssertNoProvisioning();
        }
        finally
        {
            await setup.Database.ExecuteSqlRawAsync("DROP TRIGGER reject_sign_in_commit ON \"WorkspaceUsers\"; DROP FUNCTION reject_sign_in_commit();");
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task JsonCallback_IssuesACookieOnlyForTheCommittedIdentity(bool mismatch)
    {
        if (mismatch) await SeedAccount(IdentityProvider.Google, "other", deleted: true);
        var validator = new Mock<IOidcTokenValidator>();
        validator.Setup(v => v.ValidateTokenAsync("test-token", IdentityProvider.Google)).ReturnsAsync(Identity());
        await using var app = new MembershipWebApplicationFactory(fixture.ConnectionString);
        await using var host = app.WithWebHostBuilder(builder => builder.ConfigureTestServices(services => services.AddSingleton(validator.Object)));
        using var client = host.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/auth/callback", new AuthCallbackRequest { Provider = "google", Token = "test-token" });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.Contains("Set-Cookie"));
        await using var check = fixture.CreateContext();
        var account = await check.Users.SingleAsync(user => user.ProviderSubjectId == "original");
        Assert.False(account.IsDeleted);
        Assert.Equal(mismatch ? 2 : 1, await check.Users.CountAsync());
        if (mismatch) Assert.True((await check.Users.SingleAsync(user => user.ProviderSubjectId == "other")).IsDeleted);
    }

    private async Task AssertNoProvisioning()
    {
        await using var context = fixture.CreateContext();
        Assert.Empty(await context.Users.ToListAsync());
        Assert.Empty(await context.Workspaces.ToListAsync());
        Assert.Empty(await context.WorkspaceUsers.ToListAsync());
    }

    private sealed class SignInClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class AfterSignInSave(Exception failure) : SaveChangesInterceptor
    {
        public override ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
            => ValueTask.FromException<int>(failure);
    }

    private sealed class CancelAfterSignInSave(CancellationTokenSource cancellation) : SaveChangesInterceptor
    {
        public override ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            cancellation.Cancel();
            return ValueTask.FromResult(result);
        }
    }
}
