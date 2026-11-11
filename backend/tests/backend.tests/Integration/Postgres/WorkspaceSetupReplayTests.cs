using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Tests.Integration.Postgres;

public partial class WorkspaceSetupTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Setup_RequiresAClientSuppliedNonemptyRequestIdentity(bool empty)
    {
        var request = Request();
        request.RequestId = empty ? Guid.Empty : null;
        Assert.Equal(WorkspaceSetupStatus.Invalid, (await Setup().CreateAsync(1, request)).Status);
        await AssertNothingCreated();
    }

    [Fact]
    public async Task SetupReplay_UsesTheOriginalGraphAndCurrentAccessWithoutChangingLaterEditsOrActivation()
    {
        var request = Request();
        var original = (await Setup().CreateAsync(1, request)).Workspace!;
        await using var db = fixture.CreateContext();
        await db.Workspaces.Where(w => w.Id == original.WorkspaceId).ExecuteUpdateAsync(s => s.SetProperty(w => w.Name, "Edited workspace"));
        await db.Collections.Where(c => c.Id == original.CollectionId).ExecuteUpdateAsync(s => s.SetProperty(c => c.Name, "Edited collection"));
        await db.WorkspaceUsers.Where(m => m.UserId == 1 && m.WorkspaceId == original.WorkspaceId)
            .ExecuteUpdateAsync(s => s.SetProperty(m => m.WorkspaceRole, WorkspaceRole.Normal));
        await db.Users.Where(u => u.Id == 1).ExecuteUpdateAsync(s => s.SetProperty(u => u.ActiveWorkspaceId, 1));
        // Equivalent normalized input must recover even after theme definitions change.
        request.WorkspaceName = "  New  ";
        request.CollectionName = " My Collection ";
        request.CollectionDescription = "  ";
        await db.CollectionThemes.ExecuteDeleteAsync();
        var noWrite = new BeforeMembershipSave(() => throw new InvalidOperationException("Replay cannot write"));
        var replay = await Setup(noWrite).CreateAsync(1, request);
        Assert.Equal(WorkspaceSetupStatus.Created, replay.Status);
        Assert.Equal(original.WorkspaceId, replay.Workspace!.WorkspaceId);
        Assert.Equal(original.CollectionId, replay.Workspace.CollectionId);
        Assert.Equal("Edited workspace", replay.Workspace.WorkspaceName);
        Assert.Equal("Edited collection", replay.Workspace.CollectionName);
        Assert.Equal(WorkspaceRole.Normal, replay.Workspace.WorkspaceRole);
        Assert.Equal(1, replay.Session!.Response.WorkspaceId);
        Assert.Equal(1, (await db.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
        Assert.Equal(3, await db.Workspaces.CountAsync());
        Assert.Single(await db.Collections.ToListAsync());
        Assert.Equal(1, (await db.WorkspaceStatistics.SingleAsync()).Value);
        var receipt = await db.WorkspaceSetupReceipts.SingleAsync();
        Assert.Equal(request.RequestId, receipt.RequestId);
        Assert.Equal(1, receipt.UserId);
        Assert.Equal(original.WorkspaceId, receipt.WorkspaceId);
        Assert.Equal(original.CollectionId, receipt.CollectionId);
        Assert.Equal(64, receipt.RequestHash.Length);
        Assert.Equal(Now.UtcDateTime, receipt.CreatedAt);
    }

    [Theory]
    [InlineData("workspace")]
    [InlineData("collection")]
    [InlineData("description")]
    [InlineData("theme")]
    public async Task ReusingAnIdentityWithDifferentDetails_CannotCreateAnotherWorkspace(string change)
    {
        var request = Request();
        await Setup().CreateAsync(1, request);
        switch (change)
        {
            case "workspace": request.WorkspaceName = "Another"; break;
            case "collection": request.CollectionName = "Another"; break;
            case "description": request.CollectionDescription = "Another"; break;
            case "theme": request.ThemeId = 20; break;
        }
        var result = await Setup().CreateAsync(1, request);
        Assert.Equal(WorkspaceSetupStatus.Conflict, result.Status);
        Assert.Contains("different details", result.Error);
        Assert.Null(result.Session);
        await using var db = fixture.CreateContext();
        Assert.Single(await db.WorkspaceSetupReceipts.ToListAsync());
        Assert.Single(await db.Collections.ToListAsync());
    }

    [Fact]
    public async Task CreationIdentities_AreScopedToTheAuthenticatedAccount()
    {
        var request = Request();
        var first = await Setup().CreateAsync(1, request);
        var second = await Setup().CreateAsync(3, request);
        Assert.NotEqual(first.Workspace!.WorkspaceId, second.Workspace!.WorkspaceId);
        Assert.Equal(second.Workspace.WorkspaceId, (await Setup().CreateAsync(3, request)).Workspace!.WorkspaceId);
        await using var db = fixture.CreateContext();
        Assert.Equal(2, await db.WorkspaceSetupReceipts.CountAsync());
        Assert.Equal(2, await db.Collections.CountAsync());
    }

    [Theory]
    [InlineData("left")]
    [InlineData("deleted")]
    [InlineData("purged")]
    public async Task Replay_DoesNotRestoreUnavailableWorkspacesOrLostMembership(string change)
    {
        var request = Request();
        var created = (await Setup().CreateAsync(1, request)).Workspace!;
        await using var db = fixture.CreateContext();
        await db.Users.Where(u => u.Id == 1).ExecuteUpdateAsync(s => s.SetProperty(u => u.ActiveWorkspaceId, 1));
        if (change == "left")
            await db.WorkspaceUsers.Where(m => m.UserId == 1 && m.WorkspaceId == created.WorkspaceId).ExecuteDeleteAsync();
        else if (change == "deleted")
            await db.Workspaces.Where(w => w.Id == created.WorkspaceId).ExecuteUpdateAsync(s => s.SetProperty(w => w.IsDeleted, true));
        else
        {
            await db.Categories.Where(c => c.WorkspaceId == created.WorkspaceId).ExecuteDeleteAsync();
            await db.Workspaces.Where(w => w.Id == created.WorkspaceId).ExecuteDeleteAsync();
            Assert.Null((await db.WorkspaceSetupReceipts.SingleAsync()).WorkspaceId);
        }
        var replay = await Setup().CreateAsync(1, request);
        Assert.Equal(WorkspaceSetupStatus.Unavailable, replay.Status);
        Assert.Null(replay.Workspace);
        Assert.Null(replay.Session);
        Assert.Single(await db.WorkspaceSetupReceipts.ToListAsync());
        Assert.Equal(change == "purged" ? 2 : 3, await db.Workspaces.CountAsync());
    }

    [Fact]
    public async Task DeletedInitialCollection_RemainsDeletedOnWorkspaceReplay()
    {
        var request = Request();
        var created = (await Setup().CreateAsync(1, request)).Workspace!;
        await using var db = fixture.CreateContext();
        await db.Categories.Where(c => c.CollectionId == created.CollectionId).ExecuteDeleteAsync();
        await db.Collections.Where(c => c.Id == created.CollectionId).ExecuteDeleteAsync();
        var replay = (await Setup().CreateAsync(1, request)).Workspace!;
        Assert.Equal(created.WorkspaceId, replay.WorkspaceId);
        Assert.Null(replay.CollectionId);
        Assert.Null(replay.CollectionName);
        Assert.Null((await db.WorkspaceSetupReceipts.SingleAsync()).CollectionId);
        Assert.Empty(await db.Collections.ToListAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Replay_RequiresTheOriginalAccountToRemainActive(bool purged)
    {
        var request = Request();
        await Setup().CreateAsync(1, request);
        await using var db = fixture.CreateContext();
        if (purged) await db.Users.Where(u => u.Id == 1).ExecuteDeleteAsync();
        else await db.Users.Where(u => u.Id == 1).ExecuteUpdateAsync(s => s.SetProperty(u => u.IsDeleted, true));
        var result = await Setup().CreateAsync(1, request);
        Assert.Equal(WorkspaceSetupStatus.Forbidden, result.Status);
        Assert.Null(result.Session);
        Assert.Null(result.Workspace);
        Assert.Equal(purged ? 0 : 1, await db.WorkspaceSetupReceipts.CountAsync());
        Assert.Single(await db.Collections.ToListAsync());
    }

    [Fact]
    public async Task Replay_DoesNotExposeACollectionFromAnotherWorkspace()
    {
        var request = Request();
        var created = (await Setup().CreateAsync(1, request)).Workspace!;
        var other = (await Setup().CreateAsync(3, Request())).Workspace!;
        await using var db = fixture.CreateContext();
        await db.WorkspaceSetupReceipts.Where(r => r.UserId == 1).ExecuteUpdateAsync(s => s.SetProperty(r => r.CollectionId, other.CollectionId));
        var replay = (await Setup().CreateAsync(1, request)).Workspace!;
        Assert.Equal(created.WorkspaceId, replay.WorkspaceId);
        Assert.Null(replay.CollectionId);
        Assert.Null(replay.CollectionName);
    }

    [Fact]
    public async Task ConcurrentSameIdentity_LeavesOneReceiptAndAllowsReadOnlyRecovery()
    {
        var request = Request();
        var setup = Setup(new SynchronizedSaves());
        var results = await Task.WhenAll(setup.CreateAsync(1, request), setup.CreateAsync(1, request)).WaitAsync(TimeSpan.FromSeconds(20));
        var original = Assert.Single(results, result => result.Status == WorkspaceSetupStatus.Created).Workspace!;
        Assert.Single(results, result => result.Status == WorkspaceSetupStatus.Conflict);
        Assert.Equal(original.WorkspaceId, (await Setup().CreateAsync(1, request)).Workspace!.WorkspaceId);
        await using var db = fixture.CreateContext();
        Assert.Single(await db.Collections.ToListAsync());
        Assert.Single(await db.WorkspaceSetupReceipts.ToListAsync());
    }

    [Fact]
    public async Task FailedReceiptSave_RollsBackWorkspaceMembershipGraphCounterAndActivation()
    {
        var failure = new InvalidOperationException("Receipt unavailable");
        Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() => Setup(new FailReceiptSave(failure)).CreateAsync(1, Request())));
        await AssertNothingCreated();
    }

    [Theory]
    [InlineData(PostgresErrorCodes.UniqueViolation, "PK_WorkspaceSetupReceipts", true)]
    [InlineData(PostgresErrorCodes.UniqueViolation, "Unrelated", false)]
    [InlineData(PostgresErrorCodes.ForeignKeyViolation, "Unrelated", false)]
    public async Task OnlyTheCreationReceiptUniquenessRace_IsReportedAsARetryableConflict(string code, string constraint, bool conflict)
    {
        var failure = new PostgresException("Storage failure", "ERROR", "ERROR", code, constraintName: constraint);
        var setup = Setup(new BeforeMembershipSave(() => throw failure));
        if (conflict) Assert.Equal(WorkspaceSetupStatus.Conflict, (await setup.CreateAsync(1, Request())).Status);
        else Assert.Same(failure, await Assert.ThrowsAsync<PostgresException>(() => setup.CreateAsync(1, Request())));
        await AssertNothingCreated();
    }

    [Fact]
    public async Task HttpReplay_ReturnsOriginalWorkspaceAndIssuesOnlyTheCurrentSession()
    {
        await using var factory = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var client = Client(factory, 1);
        var request = Request();
        var response = await client.PostAsJsonAsync("/api/workspaces/setup", request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var original = (await response.Content.ReadFromJsonAsync<SetupWorkspaceResponse>(JsonOptions))!;
        await using var db = fixture.CreateContext();
        await db.Users.Where(u => u.Id == 1).ExecuteUpdateAsync(s => s.SetProperty(u => u.ActiveWorkspaceId, 1));
        var replay = await client.PostAsJsonAsync("/api/workspaces/setup", request);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        Assert.Equal(original.WorkspaceId, (await replay.Content.ReadFromJsonAsync<SetupWorkspaceResponse>(JsonOptions))!.WorkspaceId);
        var cookie = Assert.Single(replay.Headers.GetValues("Set-Cookie"));
        var principal = factory.Services.GetRequiredService<ITokenService>().ValidateAppToken(cookie.Split(';')[0].Split('=', 2)[1]);
        Assert.Equal("1", principal!.FindFirst(ClaimNames.WorkspaceId)!.Value);
        Assert.Single(await db.WorkspaceSetupReceipts.ToListAsync());
        await db.WorkspaceUsers.Where(m => m.UserId == 1 && m.WorkspaceId == original.WorkspaceId).ExecuteDeleteAsync();
        var unavailable = await client.PostAsJsonAsync("/api/workspaces/setup", request);
        Assert.Equal(HttpStatusCode.Gone, unavailable.StatusCode);
        Assert.Contains("already created", await unavailable.Content.ReadAsStringAsync());
        Assert.False(unavailable.Headers.Contains("Set-Cookie"));
        Assert.Single(await db.Collections.ToListAsync());
    }

    private sealed class FailReceiptSave(Exception failure) : SaveChangesInterceptor
    {
        private int _saves;
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (++_saves == 2) throw failure;
            return ValueTask.FromResult(result);
        }
    }
}
