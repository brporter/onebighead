using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Npgsql;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Invitations;
using OneBigHead.Server.Services.Memberships;

namespace OneBigHead.Server.Tests.Integration.Postgres;

public partial class TeamInvitationsTests
{
    [Theory]
    [InlineData("empty-id")]
    [InlineData("null-token")]
    [InlineData("short-token")]
    [InlineData("wrong-token")]
    [InlineData("unknown-id")]
    [InlineData("expired")]
    [InlineData("deleted-workspace")]
    public async Task InvalidLink_CannotRevealOrGrantWorkspaceAccess(string variant)
    {
        var created = (await Invitations().InviteAsync(1, 1, Request())).Invitation!;
        var request = Access(created);
        await using (var db = fixture.CreateContext())
        {
            if (variant == "empty-id") request.InvitationId = Guid.Empty;
            if (variant == "unknown-id") request.InvitationId = Guid.NewGuid();
            if (variant == "null-token") request.Token = null!;
            if (variant == "short-token") request.Token = "short";
            if (variant == "wrong-token") request.Token = new string('x', 64);
            if (variant == "expired") (await db.WorkspaceInvitations.SingleAsync()).ExpiresAt = Now.UtcDateTime;
            if (variant == "deleted-workspace") (await db.Workspaces.SingleAsync(w => w.Id == 1)).IsDeleted = true;
            await db.SaveChangesAsync();
        }
        Assert.Null(await Preview().ReadAsync(request));
        Assert.Equal(InvitationAcceptanceStatus.Invalid, (await Acceptance().AcceptAsync(3, request)).Status);
        await using var check = fixture.CreateContext();
        Assert.Equal(7, await check.WorkspaceUsers.CountAsync());
        Assert.Null((await check.WorkspaceInvitations.SingleAsync()).AcceptedAt);
    }

    [Theory]
    [InlineData(999)]
    [InlineData(4)]
    public async Task MissingOrDeletedAccount_CannotAccept(int userId)
    {
        var created = (await Invitations().InviteAsync(1, 1, Request())).Invitation!;
        Assert.Equal(InvitationAcceptanceStatus.Unauthenticated, (await Acceptance().AcceptAsync(userId, Access(created))).Status);
    }

    [Theory]
    [InlineData(WorkspaceRole.Normal)]
    [InlineData(WorkspaceRole.WorkspaceAdmin)]
    public async Task Acceptance_AtomicallyGrantsOnlyTheLinkHolderAndReturnsItsCurrentStamp(WorkspaceRole role)
    {
        var created = (await Invitations().InviteAsync(1, 1, Request("someone-else@example.test", role))).Invitation!;
        var original = (await new CurrentUserSessionReader(Factory()).ReadAsync(3))!;
        var result = await Acceptance().AcceptAsync(3, Access(created));
        Assert.Equal(InvitationAcceptanceStatus.Joined, result.Status);
        Assert.Equal(1, result.Session!.Response.WorkspaceId);
        Assert.Equal(role, result.Session.Response.WorkspaceRole);
        Assert.Equal(ExistingEmail, result.Session.User.Email);
        Assert.NotEqual(original.User.AuthenticationStamp, result.Session.User.AuthenticationStamp);
        Assert.True(await new AccountSessionValidator(Factory()).IsCurrentAsync(3, result.Session.User.AuthenticationStamp));
        await using var check = fixture.CreateContext();
        var stored = await check.WorkspaceInvitations.SingleAsync();
        Assert.Equal(Now.UtcDateTime, stored.AcceptedAt);
        Assert.Equal(3, stored.AcceptedByUserId);
        Assert.Equal(8, await check.WorkspaceUsers.CountAsync());
        Assert.Null(await Preview().ReadAsync(Access(created)));
        Assert.Equal(InvitationAcceptanceStatus.Invalid, (await Acceptance().AcceptAsync(2, Access(created))).Status);
        Assert.Equal(InvitationCancellationStatus.NotFound, await new InvitationCancellation(Factory()).CancelAsync(1, 1, stored.Id));
        Assert.Empty((await new InvitationDirectory(Factory()).ReadAsync(1, 1))!);
    }

    [Fact]
    public async Task AcceptedLinkReplay_DoesNotUndoLaterRoleChangesSwitchesOrRemoval()
    {
        var created = (await Invitations().InviteAsync(1, 1, Request(role: WorkspaceRole.WorkspaceAdmin))).Invitation!;
        Assert.Equal(InvitationAcceptanceStatus.Joined, (await Acceptance().AcceptAsync(3, Access(created))).Status);
        await using (var db = fixture.CreateContext())
        {
            (await db.WorkspaceUsers.SingleAsync(m => m.UserId == 3 && m.WorkspaceId == 1)).WorkspaceRole = WorkspaceRole.Normal;
            (await db.Users.SingleAsync(user => user.Id == 3)).ActiveWorkspaceId = 2;
            await db.SaveChangesAsync();
        }
        var replay = await Acceptance().AcceptAsync(3, Access(created));
        Assert.Equal(InvitationAcceptanceStatus.Joined, replay.Status);
        Assert.Equal(2, replay.Session!.Response.WorkspaceId);
        await using var check = fixture.CreateContext();
        Assert.Equal(WorkspaceRole.Normal, (await check.WorkspaceUsers.SingleAsync(m => m.UserId == 3 && m.WorkspaceId == 1)).WorkspaceRole);
        await check.WorkspaceUsers.Where(m => m.UserId == 3 && m.WorkspaceId == 1).ExecuteDeleteAsync();
        Assert.Equal(InvitationAcceptanceStatus.Invalid, (await Acceptance().AcceptAsync(3, Access(created))).Status);
    }

    [Fact]
    public async Task ExistingMemberAcceptingAdminInvitation_KeepsTheirCurrentRole()
    {
        var created = (await Invitations().InviteAsync(1, 1, Request(role: WorkspaceRole.WorkspaceAdmin))).Invitation!;
        var before = (await new CurrentUserSessionReader(Factory()).ReadAsync(2))!;
        var result = await Acceptance().AcceptAsync(2, Access(created));
        Assert.Equal(InvitationAcceptanceStatus.Joined, result.Status);
        Assert.Equal(WorkspaceRole.Normal, result.Session!.Response.WorkspaceRole);
        Assert.Equal(before.User.AuthenticationStamp, result.Session.User.AuthenticationStamp);
    }

    [Fact]
    public async Task CancellationBeforeAcceptanceCommits_RollsBackMembershipAndStamp()
    {
        var created = (await Invitations().InviteAsync(1, 1, Request())).Invitation!;
        var before = (await new CurrentUserSessionReader(Factory()).ReadAsync(3))!;
        var command = Acceptance(new BeforeMembershipSave(async () =>
            Assert.Equal(InvitationCancellationStatus.Cancelled, await new InvitationCancellation(Factory()).CancelAsync(1, 1, created.Invitation.InvitationId))));
        Assert.Equal(InvitationAcceptanceStatus.Conflict, (await command.AcceptAsync(3, Access(created))).Status);
        Assert.True(await new AccountSessionValidator(Factory()).IsCurrentAsync(3, before.User.AuthenticationStamp));
        await using var check = fixture.CreateContext();
        Assert.False(await check.WorkspaceUsers.AnyAsync(m => m.UserId == 3 && m.WorkspaceId == 1));
    }

    [Fact]
    public async Task SimultaneousClaims_CannotGiveTheLinkToTwoAccounts()
    {
        var created = (await Invitations().InviteAsync(1, 1, Request())).Invitation!;
        var command = Acceptance(new SynchronizedSaves());
        var results = await Task.WhenAll(command.AcceptAsync(3, Access(created)), command.AcceptAsync(2, Access(created)));
        Assert.Single(results, result => result.Status == InvitationAcceptanceStatus.Joined);
        Assert.Single(results, result => result.Status == InvitationAcceptanceStatus.Conflict);
        await using var check = fixture.CreateContext();
        var owner = (await check.WorkspaceInvitations.SingleAsync()).AcceptedByUserId!.Value;
        Assert.Equal(InvitationAcceptanceStatus.Joined, (await Acceptance().AcceptAsync(owner, Access(created))).Status);
        Assert.Equal(InvitationAcceptanceStatus.Invalid, (await Acceptance().AcceptAsync(owner == 2 ? 3 : 2, Access(created))).Status);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Cancellation_RequiresCurrentAdminAndMapsConcurrentChanges(bool conflict)
    {
        var created = (await Invitations().InviteAsync(1, 1, Request())).Invitation!;
        Assert.Equal(InvitationCancellationStatus.Forbidden, await new InvitationCancellation(Factory()).CancelAsync(2, 1, created.Invitation.InvitationId));
        Assert.Equal(InvitationCancellationStatus.NotFound, await new InvitationCancellation(Factory()).CancelAsync(1, 2, created.Invitation.InvitationId));
        Exception failure = conflict ? new DbUpdateConcurrencyException() : new InvalidOperationException("database failed");
        var command = new InvitationCancellation(Factory(new FailDeletion(failure)));
        if (conflict) Assert.Equal(InvitationCancellationStatus.Conflict, await command.CancelAsync(1, 1, created.Invitation.InvitationId));
        else Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() => command.CancelAsync(1, 1, created.Invitation.InvitationId)));
        Assert.NotNull(await Preview().ReadAsync(Access(created)));
    }

    [Fact]
    public async Task AcceptanceFailureAndCancellation_PropagateAndLeaveTheGrantPending()
    {
        var created = (await Invitations().InviteAsync(1, 1, Request())).Invitation!;
        var failure = new InvalidOperationException("database failed");
        Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Acceptance(new BeforeMembershipSave(() => Task.FromException(failure))).AcceptAsync(3, Access(created))));
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Acceptance().AcceptAsync(3, Access(created), cancelled.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Preview().ReadAsync(Access(created), cancelled.Token));
        Assert.NotNull(await Preview().ReadAsync(Access(created)));
    }

    private InvitationAcceptance Acceptance(params IInterceptor[] interceptors) => new(Factory(interceptors), new Clock());

    [Fact]
    public async Task DeferredCommitFailure_RollsBackTheGrantConsumptionAndAuthenticationStamp()
    {
        var created = (await Invitations().InviteAsync(1, 1, Request())).Invitation!;
        var original = (await new CurrentUserSessionReader(Factory()).ReadAsync(3))!;
        await using var setup = fixture.CreateContext();
        await setup.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION acceptance_failure() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'acceptance commit failure'; END $$
            """);
        await setup.Database.ExecuteSqlRawAsync("""
            CREATE CONSTRAINT TRIGGER acceptance_failure AFTER UPDATE ON "WorkspaceInvitations"
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION acceptance_failure()
            """);
        try
        {
            await Assert.ThrowsAsync<PostgresException>(() => Acceptance().AcceptAsync(3, Access(created)));
            Assert.True(await new AccountSessionValidator(Factory()).IsCurrentAsync(3, original.User.AuthenticationStamp));
            Assert.NotNull(await Preview().ReadAsync(Access(created)));
            Assert.False(await setup.WorkspaceUsers.AnyAsync(member => member.UserId == 3 && member.WorkspaceId == 1));
            Assert.Equal(2, (await setup.Users.SingleAsync(user => user.Id == 3)).ActiveWorkspaceId);
        }
        finally
        {
            await setup.Database.ExecuteSqlRawAsync("DROP TRIGGER acceptance_failure ON \"WorkspaceInvitations\"");
            await setup.Database.ExecuteSqlRawAsync("DROP FUNCTION acceptance_failure()");
        }
    }

    [Fact]
    public async Task CancellationAfterSaving_RollsBackBeforeRotatingTheAccountStamp()
    {
        var created = (await Invitations().InviteAsync(1, 1, Request())).Invitation!;
        using var cancelled = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Acceptance(new CancelAfterSave(cancelled))
            .AcceptAsync(3, Access(created), cancelled.Token));
        Assert.NotNull(await Preview().ReadAsync(Access(created)));
        await using var check = fixture.CreateContext();
        Assert.Equal(7, await check.WorkspaceUsers.CountAsync());
    }

    [Fact]
    public async Task DeletingTheRecipient_DoesNotMakeTheConsumedLinkAvailableAgain()
    {
        var created = (await Invitations().InviteAsync(1, 1, Request())).Invitation!;
        await Acceptance().AcceptAsync(3, Access(created));
        await using var check = fixture.CreateContext();
        await check.Users.Where(user => user.Id == 3).ExecuteDeleteAsync();
        Assert.Null((await check.WorkspaceInvitations.SingleAsync()).AcceptedByUserId);
        Assert.Null(await Preview().ReadAsync(Access(created)));
        Assert.Equal(InvitationAcceptanceStatus.Invalid, (await Acceptance().AcceptAsync(2, Access(created))).Status);
    }

    private sealed class CancelAfterSave(CancellationTokenSource cancellation) : SaveChangesInterceptor
    {
        public override ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            cancellation.Cancel();
            return ValueTask.FromResult(result);
        }
    }
    private sealed class FailDeletion(Exception failure) : DbCommandInterceptor
    {
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command, CommandEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default) => ValueTask.FromException<InterceptionResult<int>>(failure);
    }
}
