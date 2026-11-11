using System.Net;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class AdministratorUserEndpointsTests(CustomWebApplicationFactory factory) : IntegrationTestBase(factory)
{
    public override async Task InitializeAsync()
    {
        // These cases remove the fixture's own default accounts; each needs fresh identities.
        await using var context = GetDbContext();
        await context.Database.EnsureDeletedAsync();
        await base.InitializeAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SelfMutation_TakesEffectInTheSessionAndRejectsTheOldAdministratorClaims(bool delete)
    {
        await using (var context = GetDbContext())
        {
            (await context.Users.SingleAsync(u => u.Id == DefaultUserId)).IsSystemAdministrator = true;
            await context.SaveChangesAsync();
        }
        Client.DefaultRequestHeaders.Add(TestAuthHandler.SystemAdministratorHeader, "true");
        var changed = delete
            ? await Client.DeleteAsync($"/api/admin/users/{DefaultUserId}")
            : await PutJsonAsync($"/api/admin/users/{DefaultUserId}/admin", new SetAdminStatusRequest { IsSystemAdministrator = false });
        Assert.Equal(delete ? HttpStatusCode.NoContent : HttpStatusCode.OK, changed.StatusCode);
        var session = await Client.GetAsync("/api/auth/me");
        if (delete) Assert.Equal(HttpStatusCode.Unauthorized, session.StatusCode);
        else
        {
            session.EnsureSuccessStatusCode();
            Assert.False((await DeserializeResponseAsync<CurrentUserResponse>(session))!.IsSystemAdministrator);
        }
        Assert.Equal(HttpStatusCode.Forbidden, (await Client.GetAsync("/api/admin/users")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await PutJsonAsync($"/api/admin/users/{DefaultUserId}/admin",
            new SetAdminStatusRequest { IsSystemAdministrator = true })).StatusCode);
        await using var check = GetDbContext();
        Assert.Equal(delete ? 0 : 1, await check.Users.CountAsync(u => u.Id == DefaultUserId));
        Assert.True(await check.Workspaces.AnyAsync(w => w.Id == DefaultWorkspaceId));
        Assert.True(await check.Users.AnyAsync(u => u.Id == DefaultNormalUserId));
    }

    [Fact]
    public async Task AccountCommands_MapMissingUsersAndPersistSuccessfulChanges()
    {
        await using (var context = GetDbContext())
        {
            (await context.Users.SingleAsync(u => u.Id == DefaultUserId)).IsSystemAdministrator = true;
            await context.SaveChangesAsync();
        }
        Assert.Equal(HttpStatusCode.NotFound, (await Client.DeleteAsync("/api/admin/users/99999")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await PutJsonAsync("/api/admin/users/99999/admin", new SetAdminStatusRequest { IsSystemAdministrator = true })).StatusCode);
        var response = await PutJsonAsync($"/api/admin/users/{DefaultNormalUserId}/admin", new SetAdminStatusRequest { IsSystemAdministrator = true });
        response.EnsureSuccessStatusCode();
        var user = (await DeserializeResponseAsync<UserSummaryResponse>(response))!;
        Assert.Equal(DefaultNormalUserId, user.UserId);
        Assert.Equal(DefaultNormalUserEmail, user.Email);
        Assert.True(user.IsSystemAdministrator);
        Assert.Equal(HttpStatusCode.NoContent, (await Client.DeleteAsync($"/api/admin/users/{DefaultNormalUserId}")).StatusCode);
        using var oldSession = CreateNormalUserClient();
        oldSession.DefaultRequestHeaders.Add(TestAuthHandler.SystemAdministratorHeader, "true");
        Assert.Equal(HttpStatusCode.Forbidden, (await oldSession.GetAsync("/api/admin/users")).StatusCode);
        await using var saved = GetDbContext();
        Assert.False(await saved.Users.AnyAsync(u => u.Id == DefaultNormalUserId));
        Assert.True(await saved.Users.AnyAsync(u => u.Id == DefaultUserId));
    }
}
