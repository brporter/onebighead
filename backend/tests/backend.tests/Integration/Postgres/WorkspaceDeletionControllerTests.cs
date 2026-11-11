using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class WorkspaceDeletionControllerTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private MembershipWebApplicationFactory Factory = null!;
    private HttpClient Client = null!;
    private OneBigHead.Server.Data.AppDbContext GetDbContext() => fixture.CreateContext();
    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var context = GetDbContext();
        context.Workspaces.Add(new Workspace { Id = 1, Name = "Current" });
        context.Users.AddRange(new User { Id = 1, Email = "admin@example.test", ActiveWorkspaceId = 1 }, new User { Id = 2, Email = "member@example.test", ActiveWorkspaceId = 1 });
        context.WorkspaceUsers.AddRange(new WorkspaceUser { UserId = 1, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.WorkspaceAdmin }, new WorkspaceUser { UserId = 2, WorkspaceId = 1 });
        context.Collections.Add(new Collection { Id = 1, WorkspaceId = 1, Name = "Collection" });
        context.Categories.Add(new Category { Id = 1, CollectionId = 1, WorkspaceId = 1, Name = "Category" });
        await context.SaveChangesAsync();
        Factory = new MembershipWebApplicationFactory(fixture.ConnectionString);
        Client = AuthenticatedClient(1, "WorkspaceAdmin");
    }
    private HttpClient AuthenticatedClient(int id, string role)
    {
        var client = Factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, id.ToString());
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, "1");
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceRoleHeader, role);
        return client;
    }
    private HttpClient CreateNormalUserClient() => AuthenticatedClient(2, "Normal");
    public async Task DisposeAsync() { Client.Dispose(); await Factory.DisposeAsync(); }

    [Fact]
    public async Task DeletingLastWorkspace_ExpiresCookieAfterCommittingAccountDeletion()
    {
        using var statsResponse = await Client.GetAsync("/api/workspaces/1/stats");
        Assert.Equal(HttpStatusCode.OK, statsResponse.StatusCode);
        var stats = await statsResponse.Content.ReadFromJsonAsync<WorkspaceStatsResponse>();
        Assert.Equal(1, stats!.CollectionCount);
        Assert.Equal(1, stats.CategoryCount);
        Assert.Equal(2, stats.UserCount);
        Assert.Equal(1, stats.AdminCount);

        using var response = await Client.DeleteAsync("/api/workspaces/1");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<WorkspaceDeletionResponse>();
        Assert.True(result!.Success);
        Assert.True(result.UserSoftDeleted);
        var cookieName = Factory.Services.GetRequiredService<IOptions<AuthenticationSettings>>().Value.Cookie.Name;
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), cookie => cookie.StartsWith(cookieName + "=;", StringComparison.Ordinal));
        await using var context = GetDbContext();
        Assert.True((await context.Users.SingleAsync(u => u.Id == 1)).IsDeleted);
        Assert.True((await context.Workspaces.SingleAsync(w => w.Id == 1)).IsDeleted);
        Assert.False((await context.Users.SingleAsync(u => u.Id == 2)).IsDeleted);
    }

    [Fact]
    public async Task DeletionCookie_UsesReplacementMembershipRoleFromCommittedState()
    {
        await using (var context = GetDbContext())
        {
            context.Workspaces.Add(new Workspace { Id = 2, Name = "Alternative" });
            context.WorkspaceUsers.Add(new WorkspaceUser { UserId = 1, WorkspaceId = 2, WorkspaceRole = WorkspaceRole.Normal });
            await context.SaveChangesAsync();
        }
        using var response = await Client.DeleteAsync("/api/workspaces/1");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<WorkspaceDeletionResponse>();
        Assert.True(result!.Success);
        Assert.False(result.UserSoftDeleted);
        Assert.Equal(2, result.NewActiveWorkspaceId);
        var cookieName = Factory.Services.GetRequiredService<IOptions<AuthenticationSettings>>().Value.Cookie.Name;
        var cookie = Assert.Single(response.Headers.GetValues("Set-Cookie"), value => value.StartsWith(cookieName + "=", StringComparison.Ordinal));
        var token = cookie[(cookieName.Length + 1)..cookie.IndexOf(';')];
        var principal = Factory.Services.GetRequiredService<ITokenService>().ValidateAppToken(token);
        Assert.NotNull(principal);
        Assert.Equal("1", principal.FindFirstValue(ClaimTypes.NameIdentifier));
        Assert.Equal("2", principal.FindFirstValue(ClaimNames.WorkspaceId));
        Assert.Equal("Normal", principal.FindFirstValue(ClaimNames.WorkspaceRole));
        await using var verification = GetDbContext();
        Assert.Equal(2, (await verification.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
    }

    [Fact]
    public async Task NormalMember_CannotReadDeletionStatsOrDeleteTheWorkspace()
    {
        using var normal = CreateNormalUserClient();
        using var stats = await normal.GetAsync("/api/workspaces/1/stats");
        using var deletion = await normal.DeleteAsync("/api/workspaces/1");
        Assert.Equal(HttpStatusCode.Forbidden, stats.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, deletion.StatusCode);
        await using var context = GetDbContext();
        Assert.False((await context.Workspaces.SingleAsync(w => w.Id == 1)).IsDeleted);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SurvivingAccount_ReceivesCurrentSnapshotEvenWithoutANewActiveWorkspace(bool alternativeDeleted)
    {
        await using (var db = GetDbContext())
        {
            db.Workspaces.Add(new Workspace { Id = 2, Name = "Alternative", IsDeleted = alternativeDeleted });
            db.WorkspaceUsers.Add(new WorkspaceUser { UserId = 1, WorkspaceId = 2, WorkspaceRole = WorkspaceRole.Normal });
            if (!alternativeDeleted) (await db.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId = 2;
            await db.SaveChangesAsync();
        }
        // A stale low-role claim must not override current database authorization.
        Client.DefaultRequestHeaders.Remove(TestAuthHandler.WorkspaceRoleHeader);
        Client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceRoleHeader, "Normal");
        var response = await Client.DeleteAsync("/api/workspaces/1");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = (await response.Content.ReadFromJsonAsync<WorkspaceDeletionResponse>())!;
        Assert.False(result.UserSoftDeleted);
        Assert.Null(result.NewActiveWorkspaceId);
        var cookie = Assert.Single(response.Headers.GetValues("Set-Cookie"));
        var principal = Factory.Services.GetRequiredService<ITokenService>().ValidateAppToken(cookie.Split(';')[0].Split('=', 2)[1]);
        Assert.NotNull(principal);
        Assert.Equal(alternativeDeleted ? null : "2", principal.FindFirstValue(ClaimNames.WorkspaceId));
        Assert.Equal("Normal", principal.FindFirstValue(ClaimNames.WorkspaceRole));
        await using var check = GetDbContext();
        var user = await check.Users.SingleAsync(u => u.Id == 1);
        Assert.False(user.IsDeleted);
        Assert.Equal(alternativeDeleted ? null : (int?)2, user.ActiveWorkspaceId);
        Assert.Equal(2, await check.WorkspaceUsers.CountAsync(m => m.UserId == 1));
    }
}
