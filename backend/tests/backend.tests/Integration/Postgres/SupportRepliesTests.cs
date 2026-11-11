using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using Npgsql;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using OneBigHead.Server.Services.Support;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class SupportRepliesTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private static readonly DateTime Now = new(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);
    private static readonly DateTime OriginalTime = Now.AddDays(-1);
    private readonly Mock<IEmailService> _email = new(MockBehavior.Strict);
    private readonly Mock<ILogger<SupportReplies>> _log = new();

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var db = fixture.CreateContext();
        db.Workspaces.Add(new Workspace { Id = 1, Name = "Workspace", Slug = "workspace" });
        db.Users.AddRange(Enumerable.Range(1, 4).Select(id => new User
        {
            Id = id, Email = $"user-{id}@example.test", ActiveWorkspaceId = 1,
            IsSystemAdministrator = id >= 3, IsDeleted = id == 4
        }));
        db.WorkspaceUsers.AddRange(Enumerable.Range(1, 4).Select(id => new WorkspaceUser
        {
            UserId = id, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.Normal
        }));
        db.SupportRequests.AddRange(Enumerable.Range(10, 4).Select(id => new SupportRequest
        {
            Id = id, UserId = id == 12 ? null : id == 11 ? 2 : 1, Email = $"ticket-{id}@example.test",
            Subject = $"Ticket {id}", Description = "Original description", Status = SupportRequestStatus.Resolved,
            CreatedAt = OriginalTime, UpdatedAt = OriginalTime, IsDeleted = id == 13,
            DeletedAt = id == 13 ? OriginalTime : null
        }));
        await db.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData(false, SupportRequestStatus.Open, SupportRequestStatus.Open)]
    [InlineData(false, SupportRequestStatus.InProgress, SupportRequestStatus.InProgress)]
    [InlineData(false, SupportRequestStatus.Resolved, SupportRequestStatus.Open)]
    [InlineData(false, SupportRequestStatus.Closed, SupportRequestStatus.Open)]
    [InlineData(true, SupportRequestStatus.Open, SupportRequestStatus.InProgress)]
    [InlineData(true, SupportRequestStatus.InProgress, SupportRequestStatus.InProgress)]
    [InlineData(true, SupportRequestStatus.Resolved, SupportRequestStatus.Resolved)]
    [InlineData(true, SupportRequestStatus.Closed, SupportRequestStatus.Closed)]
    public async Task Reply_SavesMessageTimestampReadStateAndStatusTogether(bool admin, SupportRequestStatus before, SupportRequestStatus after)
    {
        await using var setup = fixture.CreateContext();
        await setup.SupportRequests.Where(r => r.Id == 10).ExecuteUpdateAsync(s => s.SetProperty(r => r.Status, before));
        if (admin) ExpectNotification(10, true);
        const string message = "  Follow up\nSecond line  ";
        var result = await Send(Service(), admin, 10, admin ? 3 : 1, message);
        Assert.Equal(SupportReplyStatus.Added, result.Status);
        var dto = Assert.IsType<SupportReplyDto>(result.Reply);
        Assert.Equal(10, dto.SupportRequestId);
        Assert.Equal(admin ? 3 : 1, dto.UserId);
        Assert.Equal(message, dto.Message);
        Assert.Equal(admin, dto.IsFromAdmin);
        Assert.Equal(!admin, dto.IsRead);
        Assert.Equal(Now, dto.CreatedAt);
        await using var check = fixture.CreateContext();
        var saved = await check.SupportReplies.SingleAsync();
        Assert.Equal(dto.SupportReplyId, saved.Id);
        Assert.Equal(message, saved.Message);
        var ticket = await check.SupportRequests.SingleAsync(r => r.Id == 10);
        Assert.Equal(after, ticket.Status);
        Assert.Equal(Now, ticket.UpdatedAt);
        Assert.Equal(OriginalTime, ticket.CreatedAt);
        Assert.Equal("Original description", ticket.Description);
        Assert.Equal(1, ticket.UserId);
        Assert.False(ticket.IsDeleted);
        _email.VerifyAll();
        _email.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(false, 999, 10, SupportReplyStatus.Forbidden)]
    [InlineData(false, 4, 10, SupportReplyStatus.Forbidden)]
    [InlineData(true, 999, 10, SupportReplyStatus.Forbidden)]
    [InlineData(true, 4, 10, SupportReplyStatus.Forbidden)]
    [InlineData(true, 1, 10, SupportReplyStatus.Forbidden)]
    [InlineData(false, 1, 999, SupportReplyStatus.NotFound)]
    [InlineData(true, 3, 999, SupportReplyStatus.NotFound)]
    [InlineData(false, 1, 11, SupportReplyStatus.NotFound)]
    [InlineData(false, 1, 12, SupportReplyStatus.NotFound)]
    [InlineData(false, 1, 13, SupportReplyStatus.Invalid)]
    [InlineData(true, 3, 13, SupportReplyStatus.Invalid)]
    public async Task Reply_RequiresCurrentAccountAuthorityAndAccessibleActiveTicket(bool admin, int user, int ticket, SupportReplyStatus expected)
    {
        var result = await Send(Service(), admin, ticket, user, "Reply");
        Assert.Equal(expected, result.Status);
        Assert.Null(result.Reply);
        if (expected == SupportReplyStatus.Invalid) Assert.Contains("deleted", result.Error);
        await AssertNoWrites();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" \t\n")]
    public async Task EmptyReply_IsRejectedBeforeWriting(string? message)
    {
        Assert.Equal(SupportReplyStatus.Invalid, (await Service().AddUserReplyAsync(10, 1, message!)).Status);
        await AssertNoWrites();
    }

    [Fact]
    public async Task MessageLimit_IsEnforcedWithAnInclusiveBoundary()
    {
        var invalid = await Service().AddUserReplyAsync(10, 1, new string('a', 4001));
        Assert.Equal(SupportReplyStatus.Invalid, invalid.Status);
        Assert.Contains("4000", invalid.Error);
        await AssertNoWrites();
        var valid = await Service().AddUserReplyAsync(10, 1, new string('a', 4000));
        Assert.Equal(SupportReplyStatus.Added, valid.Status);
        await using var db = fixture.CreateContext();
        Assert.Equal(4000, (await db.SupportReplies.SingleAsync()).Message.Length);
    }

    [Theory]
    [InlineData(11, true)]
    [InlineData(12, false)]
    public async Task AdminReply_NotifiesTicketRecipientOnlyAfterCommit(int ticket, bool registered)
    {
        _email.Setup(e => e.SendSupportReplyNotificationAsync($"ticket-{ticket}@example.test", $"Ticket {ticket}", "Reply", ticket, registered))
            .Returns(async () =>
            {
                // A separate connection cannot see an uncommitted reply.
                await using var check = fixture.CreateContext();
                var saved = await check.SupportReplies.SingleAsync();
                Assert.Equal(ticket, saved.SupportRequestId);
                Assert.Equal(Now, (await check.SupportRequests.SingleAsync(r => r.Id == ticket)).UpdatedAt);
            });
        Assert.Equal(SupportReplyStatus.Added, (await Service().AddAdminReplyAsync(ticket, 3, "Reply")).Status);
        _email.VerifyAll();
    }

    [Fact]
    public async Task NotificationFailure_StillReturnsTheCommittedReplyAndLogsDeliveryFailure()
    {
        var failure = new InvalidOperationException("Fictional mail delivery failure");
        _email.Setup(e => e.SendSupportReplyNotificationAsync("ticket-10@example.test", "Ticket 10", "Reply", 10, true)).ThrowsAsync(failure);
        var result = await Service().AddAdminReplyAsync(10, 3, "Reply");
        Assert.Equal(SupportReplyStatus.Added, result.Status);
        await using var check = fixture.CreateContext();
        Assert.Equal(result.Reply!.SupportReplyId, (await check.SupportReplies.SingleAsync()).Id);
        var warning = Assert.Single(_log.Invocations, i => i.Method.Name == "Log");
        Assert.Equal(LogLevel.Warning, warning.Arguments[0]);
        Assert.Same(failure, warning.Arguments[3]);
        Assert.Contains(result.Reply.SupportReplyId.ToString(), warning.Arguments[2].ToString());
    }

    [Fact]
    public async Task ConcurrentReplies_DoNotSilentlyOverwriteTicketTransitions()
    {
        ExpectNotification(10, true);
        var service = Service(new SynchronizedSaves());
        var results = await Task.WhenAll(service.AddUserReplyAsync(10, 1, "User reply"),
            service.AddAdminReplyAsync(10, 3, "Admin reply")).WaitAsync(TimeSpan.FromSeconds(20));
        var saved = Assert.Single(results, r => r.Status == SupportReplyStatus.Added);
        var conflict = Assert.Single(results, r => r.Status == SupportReplyStatus.Conflict);
        Assert.Null(conflict.Reply);
        Assert.Contains("Refresh", conflict.Error);
        await using var check = fixture.CreateContext();
        var reply = await check.SupportReplies.SingleAsync();
        Assert.Equal(saved.Reply!.SupportReplyId, reply.Id);
        Assert.Equal(reply.IsFromAdmin ? SupportRequestStatus.Resolved : SupportRequestStatus.Open,
            (await check.SupportRequests.SingleAsync(r => r.Id == 10)).Status);
        Assert.Equal(reply.IsFromAdmin ? 1 : 0, _email.Invocations.Count);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TicketChangedBeforeSave_RequiresReviewAndSendsNoNotification(bool delete)
    {
        var concurrent = new BeforeMembershipSave(async () =>
        {
            var repository = new SupportRepository(fixture.CreateContextFactory());
            if (delete) Assert.True(await repository.SoftDeleteAsync(10));
            else Assert.NotNull(await repository.UpdateStatusAsync(10, SupportRequestStatus.Closed));
        });
        var result = await Service(concurrent).AddAdminReplyAsync(10, 3, "Stale reply");
        Assert.Equal(SupportReplyStatus.Conflict, result.Status);
        await using var check = fixture.CreateContext();
        Assert.Empty(await check.SupportReplies.ToListAsync());
        var ticket = await check.SupportRequests.SingleAsync(r => r.Id == 10);
        Assert.Equal(delete, ticket.IsDeleted);
        Assert.Equal(delete ? SupportRequestStatus.Resolved : SupportRequestStatus.Closed, ticket.Status);
        _email.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task FailedSave_PropagatesWithoutPersistingReplyOrTicketChange()
    {
        var error = new InvalidOperationException("Injected storage failure");
        var command = Service(new BeforeMembershipSave(() => throw error));
        Assert.Same(error, await Assert.ThrowsAsync<InvalidOperationException>(() => command.AddAdminReplyAsync(10, 3, "Reply")));
        await AssertNoWrites();
    }

    [Fact]
    public async Task FailedCommit_RollsBackSavedReplyAndTicketTransitionBeforeNotification()
    {
        await using var db = fixture.CreateContext();
        await db.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION support_reply_failure() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'Injected support commit failure'; END $$;
            CREATE CONSTRAINT TRIGGER support_reply_failure AFTER INSERT ON "SupportReplies"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION support_reply_failure();
            """);
        try
        {
            var observed = new ObserveSavedReply();
            await Assert.ThrowsAsync<PostgresException>(() => Service(observed).AddUserReplyAsync(10, 1, "Reply"));
            Assert.True(observed.Seen);
            await AssertNoWrites();
        }
        finally
        {
            await db.Database.ExecuteSqlRawAsync("DROP TRIGGER support_reply_failure ON \"SupportReplies\"; DROP FUNCTION support_reply_failure()");
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HttpReply_UsesRegisteredCommandAndPreservesResponseContract(bool admin)
    {
        if (admin) ExpectNotification(10, true);
        using var factory = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var host = factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services => services.AddSingleton(_email.Object)));
        using var client = host.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, admin ? "3" : "1");
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, "1");
        client.DefaultRequestHeaders.Add(TestAuthHandler.SystemAdministratorHeader, admin ? "true" : "false");
        var response = await client.PostAsJsonAsync(admin ? "/api/admin/support/10/reply" : "/api/support/10/reply", new { message = "HTTP reply" });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var dto = await response.Content.ReadFromJsonAsync<SupportReplyDto>();
        Assert.NotNull(dto);
        Assert.Equal("HTTP reply", dto.Message);
        Assert.Equal(admin, dto.IsFromAdmin);
        Assert.Equal(!admin, dto.IsRead);
        var read = await client.GetFromJsonAsync<SupportRequestDto>(admin ? "/api/admin/support/10" : "/api/support/10");
        Assert.Equal(dto.SupportReplyId, Assert.Single(read!.Replies).SupportReplyId);
        Assert.Equal(admin ? "Resolved" : "Open", read.Status);
        _email.VerifyAll();
    }

    [Theory]
    [InlineData(1, 11, false, HttpStatusCode.NotFound)]
    [InlineData(1, 12, false, HttpStatusCode.NotFound)]
    [InlineData(1, 13, false, HttpStatusCode.BadRequest)]
    [InlineData(1, 10, true, HttpStatusCode.Forbidden)]
    public async Task HttpReply_DoesNotTrustTicketIdsOrAdministratorClaims(int user, int ticket, bool admin, HttpStatusCode expected)
    {
        using var factory = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, user.ToString());
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, "1");
        client.DefaultRequestHeaders.Add(TestAuthHandler.SystemAdministratorHeader, "true");
        var response = await client.PostAsJsonAsync($"/api/{(admin ? "admin/support" : "support")}/{ticket}/reply", new { message = "Reply" });
        Assert.Equal(expected, response.StatusCode);
        await AssertNoWrites();
    }

    private SupportReplies Service(params IInterceptor[] interceptors) => new(
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString)
            .AddInterceptors(interceptors).Options), _email.Object, new Clock(), _log.Object);

    private static Task<SupportReplyResult> Send(ISupportReplies service, bool admin, int ticket, int user, string message) =>
        admin ? service.AddAdminReplyAsync(ticket, user, message) : service.AddUserReplyAsync(ticket, user, message);

    private void ExpectNotification(int ticket, bool registered) =>
        _email.Setup(e => e.SendSupportReplyNotificationAsync($"ticket-{ticket}@example.test", $"Ticket {ticket}", It.IsAny<string>(), ticket, registered))
            .Returns(Task.CompletedTask);

    private async Task AssertNoWrites()
    {
        await using var check = fixture.CreateContext();
        Assert.Empty(await check.SupportReplies.ToListAsync());
        Assert.All(await check.SupportRequests.ToListAsync(), r =>
        {
            Assert.Equal(SupportRequestStatus.Resolved, r.Status);
            Assert.Equal(OriginalTime, r.UpdatedAt);
        });
        _email.VerifyNoOtherCalls();
    }

    private sealed class Clock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => new(Now);
    }

    private sealed class ObserveSavedReply : SaveChangesInterceptor
    {
        public bool Seen { get; private set; }
        public override async ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            var context = (AppDbContext)eventData.Context!;
            Seen = await context.SupportReplies.AsNoTracking().AnyAsync(cancellationToken);
            Assert.Equal(SupportRequestStatus.Open, (await context.SupportRequests.AsNoTracking().SingleAsync(r => r.Id == 10, cancellationToken)).Status);
            return result;
        }
    }
}
