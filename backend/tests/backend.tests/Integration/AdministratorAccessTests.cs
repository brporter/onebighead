using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class AdministratorAccessTests(CustomWebApplicationFactory factory) : IntegrationTestBase(factory)
{
    protected override async Task SeedAdditionalDataAsync()
    {
        await using var context = GetDbContext();
        foreach (var user in await context.Users.ToListAsync())
        {
            user.IsSystemAdministrator = false;
            user.IsDeleted = false;
        }
        foreach (var workspace in await context.Workspaces.ToListAsync()) workspace.IsDeleted = false;
        await context.SaveChangesAsync();
    }

    [Theory]
    [InlineData("GET", "/api/admin/workspaces")]
    [InlineData("DELETE", "/api/admin/workspaces/1")]
    [InlineData("GET", "/api/admin/users")]
    [InlineData("DELETE", "/api/admin/users/2")]
    [InlineData("PUT", "/api/admin/users/2/admin")]
    [InlineData("GET", "/api/admin/templates")]
    [InlineData("GET", "/api/admin/templates/1")]
    [InlineData("POST", "/api/admin/templates")]
    [InlineData("PUT", "/api/admin/templates/1")]
    [InlineData("DELETE", "/api/admin/templates/1")]
    [InlineData("GET", "/api/admin/support")]
    [InlineData("GET", "/api/admin/support/1")]
    [InlineData("POST", "/api/admin/support/1/reply")]
    [InlineData("PUT", "/api/admin/support/1/status")]
    [InlineData("DELETE", "/api/admin/support/1")]
    public async Task StaleAdministratorRole_CannotAccessAnyAdministrationEndpoint(string method, string path)
    {
        Client.DefaultRequestHeaders.Add(TestAuthHandler.SystemAdministratorHeader, "true");
        using var request = new HttpRequestMessage(new HttpMethod(method), path)
        { Content = JsonContent.Create(new { name = "Blocked", isSystemAdministrator = true, message = "Blocked", status = "Closed" }) };
        Assert.Equal(HttpStatusCode.Forbidden, (await Client.SendAsync(request)).StatusCode);
        await using var context = GetDbContext();
        Assert.False((await context.Users.SingleAsync(u => u.Id == DefaultNormalUserId)).IsSystemAdministrator);
        Assert.True(await context.Workspaces.AnyAsync(w => w.Id == DefaultWorkspaceId));
        Assert.Equal("General Item", (await context.ItemTemplates.SingleAsync(t => t.Id == 1)).Name);
        Assert.False(await context.SupportReplies.AnyAsync());
    }

    [Fact]
    public async Task DirectoryEndpoints_UseRegisteredQueriesAndForwardTheEmailFilter()
    {
        await using (var context = GetDbContext())
        {
            (await context.Users.SingleAsync(u => u.Id == DefaultUserId)).IsSystemAdministrator = true;
            await context.SaveChangesAsync();
        }
        var workspaceResponse = await Client.GetAsync("/api/admin/workspaces");
        workspaceResponse.EnsureSuccessStatusCode();
        var workspace = Assert.Single((await DeserializeResponseAsync<List<WorkspaceSummaryResponse>>(workspaceResponse))!);
        Assert.Equal(DefaultWorkspaceId, workspace.WorkspaceId);
        Assert.Equal(2, workspace.UserCount);
        Assert.Equal(1, workspace.CollectionCount);
        var userResponse = await Client.GetAsync("/api/admin/users?email=%20NORMAL%20");
        userResponse.EnsureSuccessStatusCode();
        var user = Assert.Single((await DeserializeResponseAsync<List<UserSummaryResponse>>(userResponse))!);
        Assert.Equal(DefaultNormalUserId, user.UserId);
        Assert.Equal(workspace.Name, user.WorkspaceName);
    }

    [Theory]
    [InlineData("/api/admin/templates", false)]
    [InlineData("/api/admin/support", false)]
    [InlineData("/api/admin/workspaces", false)]
    [InlineData("/api/admin/templates", true)]
    [InlineData("/api/admin/support", true)]
    [InlineData("/api/admin/workspaces", true)]
    public async Task GlobalAdministration_DoesNotRequireAnActiveWorkspace_ButDoesRequireAnActiveAccount(string path, bool deletedAccount)
    {
        await using (var context = GetDbContext())
        {
            var user = await context.Users.SingleAsync(u => u.Id == DefaultUserId);
            user.IsSystemAdministrator = true;
            user.IsDeleted = deletedAccount;
            (await context.Workspaces.SingleAsync(w => w.Id == DefaultWorkspaceId)).IsDeleted = true;
            await context.SaveChangesAsync();
        }
        Assert.Equal(deletedAccount ? HttpStatusCode.Forbidden : HttpStatusCode.OK, (await Client.GetAsync(path)).StatusCode);
    }

    [Fact]
    public async Task RoleChanges_TakeEffectOnTheNextRequest_AndMatchTheSessionResponse()
    {
        await using (var context = GetDbContext())
        {
            (await context.Users.SingleAsync(u => u.Id == DefaultUserId)).IsSystemAdministrator = true;
            await context.SaveChangesAsync();
        }
        using var subject = CreateNormalUserClient();
        Assert.Equal(HttpStatusCode.Forbidden, (await subject.GetAsync("/api/admin/templates")).StatusCode);
        (await PutJsonAsync($"/api/admin/users/{DefaultNormalUserId}/admin", new SetAdminStatusRequest { IsSystemAdministrator = true })).EnsureSuccessStatusCode();
        // The promoted user still has their original token with no administrator role.
        (await subject.GetAsync("/api/admin/templates")).EnsureSuccessStatusCode();
        (await subject.GetAsync("/api/admin/support")).EnsureSuccessStatusCode();
        Assert.True(await SessionReportsAdministrator(subject));
        (await PutJsonAsync($"/api/admin/users/{DefaultNormalUserId}/admin", new SetAdminStatusRequest { IsSystemAdministrator = false })).EnsureSuccessStatusCode();
        subject.DefaultRequestHeaders.Add(TestAuthHandler.SystemAdministratorHeader, "true");
        Assert.Equal(HttpStatusCode.Forbidden, (await subject.GetAsync("/api/admin/templates")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await subject.GetAsync("/api/admin/support")).StatusCode);
        Assert.False(await SessionReportsAdministrator(subject));
    }

    [Fact]
    public async Task DeletedAdministrator_CannotUseAStillValidTokenRole()
    {
        await using var context = GetDbContext();
        var user = await context.Users.SingleAsync(u => u.Id == DefaultUserId);
        user.IsSystemAdministrator = true;
        user.IsDeleted = true;
        await context.SaveChangesAsync();
        Client.DefaultRequestHeaders.Add(TestAuthHandler.SystemAdministratorHeader, "true");
        Assert.Equal(HttpStatusCode.Forbidden, (await Client.GetAsync("/api/admin/templates")).StatusCode);
        Assert.False(await SessionReportsAdministrator(Client));
    }

    private static async Task<bool> SessionReportsAdministrator(HttpClient client)
    {
        var response = await client.GetAsync("/api/auth/me");
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("isSystemAdministrator").GetBoolean();
    }
}
