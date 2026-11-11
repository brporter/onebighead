using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Npgsql;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Memberships;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class WorkspaceAdminTransferTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 12, 0, 0, 789, TimeSpan.Zero);
    private static readonly DateTime RevokedAt = new(2026, 11, 10, 12, 0, 0, DateTimeKind.Utc);

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var db = fixture.CreateContext();
        db.Workspaces.AddRange(new Workspace { Id = 1, Name = "Transfer" },
            new Workspace { Id = 2, Name = "Other" }, new Workspace { Id = 3, Name = "Deleted", IsDeleted = true });
        db.Users.AddRange(new User { Id = 1, Email = "owner@example.test", ActiveWorkspaceId = 1 },
            new User { Id = 2, Email = "recipient@example.test", ActiveWorkspaceId = 1 },
            new User { Id = 3, Email = "deleted@example.test", ActiveWorkspaceId = 1, IsDeleted = true },
            new User { Id = 4, Email = "outsider@example.test", ActiveWorkspaceId = 2 });
        db.WorkspaceUsers.AddRange(new WorkspaceUser { UserId = 1, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
            new WorkspaceUser { UserId = 1, WorkspaceId = 2, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
            new WorkspaceUser { UserId = 1, WorkspaceId = 3, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
            new WorkspaceUser { UserId = 2, WorkspaceId = 1 },
            new WorkspaceUser { UserId = 3, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
            new WorkspaceUser { UserId = 4, WorkspaceId = 2, WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
        db.TokenRevocations.Add(new TokenRevocation { UserId = 1, RevokedAtUtc = RevokedAt.AddDays(-1) });
        await db.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData(999, 1, 2, WorkspaceAdminTransferStatus.NotFound)]
    [InlineData(3, 1, 2, WorkspaceAdminTransferStatus.NotFound)]
    [InlineData(4, 1, 2, WorkspaceAdminTransferStatus.NotFound)]
    [InlineData(1, 999, 2, WorkspaceAdminTransferStatus.NotFound)]
    [InlineData(1, 3, 2, WorkspaceAdminTransferStatus.NotFound)]
    [InlineData(2, 1, 1, WorkspaceAdminTransferStatus.Forbidden)]
    [InlineData(1, 1, 1, WorkspaceAdminTransferStatus.Invalid)]
    [InlineData(1, 1, 0, WorkspaceAdminTransferStatus.Invalid)]
    [InlineData(1, 1, 999, WorkspaceAdminTransferStatus.Invalid)]
    [InlineData(1, 1, 3, WorkspaceAdminTransferStatus.Invalid)]
    [InlineData(1, 1, 4, WorkspaceAdminTransferStatus.Invalid)]
    public async Task InvalidTransfer_DoesNotChangeRolesOrRevocations(int actor, int workspace, int recipient, WorkspaceAdminTransferStatus expected)
    {
        var result = await Command().TransferAsync(actor, workspace, recipient);
        Assert.Equal(expected, result.Status);
        Assert.Null(result.Session);
        await AssertUnchanged();
    }

    [Theory]
    [InlineData(1, WorkspaceRole.Normal)]
    [InlineData(2, WorkspaceRole.WorkspaceAdmin)]
    [InlineData(3, WorkspaceRole.Normal)]
    [InlineData(null, WorkspaceRole.Normal)]
    public async Task Transfer_CommitsRolesAndRevocationsThenReturnsCurrentSession(int? activeWorkspace, WorkspaceRole activeRole)
    {
        await using (var db = fixture.CreateContext())
        {
            (await db.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId = activeWorkspace;
            await db.SaveChangesAsync();
        }
        var result = await Command().TransferAsync(1, 1, 2);
        {
            // A different connection sees the complete result after the command completes.
            using var committed = fixture.CreateContext();
            Assert.Equal(2, committed.TokenRevocations.Count());
            Assert.Equal(WorkspaceRole.Normal, committed.WorkspaceUsers.Single(m => m.UserId == 1 && m.WorkspaceId == 1).WorkspaceRole);
            Assert.Equal(WorkspaceRole.WorkspaceAdmin, committed.WorkspaceUsers.Single(m => m.UserId == 2 && m.WorkspaceId == 1).WorkspaceRole);
        }
        Assert.Equal(WorkspaceAdminTransferStatus.Transferred, result.Status);
        Assert.Equal(activeWorkspace == 3 ? null : activeWorkspace, result.Session!.User.ActiveWorkspaceId);
        Assert.Equal(activeRole, result.Session.Response.WorkspaceRole);
        Assert.Equal(new[] { 1, 2 }, result.Session.Response.Workspaces.Select(m => m.WorkspaceId));
        Assert.Equal(WorkspaceRole.Normal, result.Session.Response.Workspaces[0].WorkspaceRole);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, result.Session.Response.Workspaces[1].WorkspaceRole);
        await using var check = fixture.CreateContext();
        Assert.All(await check.TokenRevocations.ToListAsync(), r => Assert.Equal(RevokedAt, r.RevokedAtUtc));
        Assert.Equal(activeWorkspace, (await check.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
    }

    [Fact]
    public async Task TransferToExistingAdmin_PreservesLaterAuditAndInvalidatesBothAccountSnapshots()
    {
        var repository = new TokenRevocationRepository(fixture.CreateContextFactory());
        var sessions = new AccountSessionValidator(fixture.CreateContextFactory());
        Guid actorStamp, recipientStamp;
        await using (var db = fixture.CreateContext())
        {
            actorStamp = (await db.Users.SingleAsync(user => user.Id == 1)).AuthenticationStamp;
            recipientStamp = (await db.Users.SingleAsync(user => user.Id == 2)).AuthenticationStamp;
            (await db.WorkspaceUsers.SingleAsync(m => m.UserId == 2 && m.WorkspaceId == 1)).WorkspaceRole = WorkspaceRole.WorkspaceAdmin;
            db.TokenRevocations.Add(new TokenRevocation { UserId = 2, RevokedAtUtc = RevokedAt.AddHours(1) });
            await db.SaveChangesAsync();
        }
        Assert.True(await sessions.IsCurrentAsync(1, actorStamp));
        Assert.True(await sessions.IsCurrentAsync(2, recipientStamp));
        var command = Command();
        var result = await command.TransferAsync(1, 1, 2);
        Assert.Equal(WorkspaceAdminTransferStatus.Transferred, result.Status);
        Assert.False(await sessions.IsCurrentAsync(1, actorStamp));
        Assert.False(await sessions.IsCurrentAsync(2, recipientStamp));
        Assert.True(await sessions.IsCurrentAsync(1, result.Session!.User.AuthenticationStamp));
        Assert.Equal(RevokedAt.AddHours(1), await repository.GetRevokedAtUtcAsync(2));
        Assert.Equal(WorkspaceAdminTransferStatus.Forbidden, (await command.TransferAsync(1, 1, 2)).Status);
    }

    [Fact]
    public async Task CommitFailure_AfterBothRolesAndRevocations_RollsBackEveryWrite()
    {
        await using var setup = fixture.CreateContext();
        await setup.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION transfer_failure() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'Admin transfer test failure'; END $$
            """);
        await setup.Database.ExecuteSqlRawAsync("""
            CREATE CONSTRAINT TRIGGER transfer_failure AFTER INSERT OR UPDATE ON "TokenRevocations"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION transfer_failure()
            """);
        try
        {
            var observation = new ObserveRevocations();
            var logger = new Mock<ILogger<WorkspaceAdminTransfer>>(MockBehavior.Strict);
            var command = new WorkspaceAdminTransfer(Factory(observation), new Clock(), logger.Object);
            await Assert.ThrowsAsync<PostgresException>(() => command.TransferAsync(1, 1, 2));
            Assert.True(observation.WritesVerified);
            logger.VerifyNoOtherCalls();
            await AssertUnchanged();
        }
        finally
        {
            await setup.Database.ExecuteSqlRawAsync("DROP TRIGGER transfer_failure ON \"TokenRevocations\"");
            await setup.Database.ExecuteSqlRawAsync("DROP FUNCTION transfer_failure()");
        }
    }

    [Fact]
    public async Task CompetingTransfers_CommitOnceAndReportConflictWithoutPartialRevocation()
    {
        var command = Command(new SynchronizedSaves());
        var outcomes = await Task.WhenAll(command.TransferAsync(1, 1, 2), command.TransferAsync(1, 1, 2)).WaitAsync(TimeSpan.FromSeconds(20));
        Assert.Single(outcomes, r => r.Status == WorkspaceAdminTransferStatus.Transferred);
        Assert.Single(outcomes, r => r.Status == WorkspaceAdminTransferStatus.Conflict && r.Error!.Contains("Reload"));
        await using var check = fixture.CreateContext();
        Assert.Equal(2, await check.TokenRevocations.CountAsync());
        Assert.Equal(WorkspaceRole.Normal, (await check.WorkspaceUsers.SingleAsync(m => m.UserId == 1 && m.WorkspaceId == 1)).WorkspaceRole);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, (await check.WorkspaceUsers.SingleAsync(m => m.UserId == 2 && m.WorkspaceId == 1)).WorkspaceRole);
    }

    [Fact]
    public async Task RecipientRemovedAfterValidation_PreservesOriginalAdminAndRevocation()
    {
        var command = Command(new BeforeMembershipSave(async () =>
        {
            await using var db = fixture.CreateContext();
            await db.WorkspaceUsers.Where(m => m.UserId == 2 && m.WorkspaceId == 1).ExecuteDeleteAsync();
        }));
        Assert.Equal(WorkspaceAdminTransferStatus.Conflict, (await command.TransferAsync(1, 1, 2)).Status);
        await AssertUnchanged();
    }

    [Fact]
    public async Task Endpoint_UsesRegisteredTransactionAndRefreshesCookieWithDemotedRole()
    {
        await using var factory = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, "1");
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, "1");
        var result = await client.PostAsJsonAsync("/api/workspaces/1/transfer-admin", new TransferAdminRequest { NewAdminUserId = 2 });
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        Assert.True((await result.Content.ReadFromJsonAsync<TransferAdminResponse>())!.Success);
        var cookie = Assert.Single(result.Headers.GetValues("Set-Cookie"));
        var token = cookie.Split(';')[0].Split('=', 2)[1];
        var principal = factory.Services.GetRequiredService<ITokenService>().ValidateAppToken(token);
        Assert.Equal("Normal", principal!.FindFirst(ClaimNames.WorkspaceRole)!.Value);
        Assert.IsType<AccountSessionValidator>(factory.Services.GetRequiredService<IAccountSessionValidator>());
        await using var db = fixture.CreateContext();
        Assert.Equal(2, await db.TokenRevocations.CountAsync());
        // The test auth header still claims admin, but current membership decides.
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync("/api/workspaces/1/transfer-admin", new TransferAdminRequest { NewAdminUserId = 2 })).StatusCode);
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync("/api/workspaces/1/transfer-admin", new TransferAdminRequest { NewAdminUserId = 2 })).StatusCode);
    }

    private WorkspaceAdminTransfer Command(params IInterceptor[] interceptors) =>
        new(Factory(interceptors), new Clock(), NullLogger<WorkspaceAdminTransfer>.Instance);

    private IDbContextFactory<AppDbContext> Factory(params IInterceptor[] interceptors) => new TestDbContextFactory(
        new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString).AddInterceptors(interceptors).Options);

    private async Task AssertUnchanged()
    {
        await using var check = fixture.CreateContext();
        Assert.All(await check.WorkspaceUsers.Where(m => m.UserId == 1).ToListAsync(), m => Assert.Equal(WorkspaceRole.WorkspaceAdmin, m.WorkspaceRole));
        Assert.All(await check.WorkspaceUsers.Where(m => m.UserId == 2).ToListAsync(), m => Assert.Equal(WorkspaceRole.Normal, m.WorkspaceRole));
        var revocation = Assert.Single(await check.TokenRevocations.ToListAsync());
        Assert.Equal(1, revocation.UserId);
        Assert.Equal(RevokedAt.AddDays(-1), revocation.RevokedAtUtc);
    }

    private sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }

    private sealed class ObserveRevocations : DbCommandInterceptor
    {
        private int _writes;
        public bool WritesVerified { get; private set; }
        public override async ValueTask<int> NonQueryExecutedAsync(DbCommand command, CommandExecutedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.StartsWith("INSERT INTO \"TokenRevocations\"", StringComparison.Ordinal) && ++_writes == 2)
            {
                var db = (AppDbContext)eventData.Context!;
                Assert.All(await db.TokenRevocations.ToListAsync(cancellationToken), r => Assert.Equal(RevokedAt, r.RevokedAtUtc));
                Assert.Equal(2, await db.TokenRevocations.CountAsync(cancellationToken));
                Assert.Equal(WorkspaceRole.Normal, await db.WorkspaceUsers.Where(m => m.UserId == 1 && m.WorkspaceId == 1).Select(m => m.WorkspaceRole).SingleAsync(cancellationToken));
                Assert.Equal(WorkspaceRole.WorkspaceAdmin, await db.WorkspaceUsers.Where(m => m.UserId == 2 && m.WorkspaceId == 1).Select(m => m.WorkspaceRole).SingleAsync(cancellationToken));
                WritesVerified = true;
            }
            return result;
        }
    }

}
