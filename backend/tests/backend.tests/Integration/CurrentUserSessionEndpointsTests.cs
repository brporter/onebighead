using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

public class CurrentUserSessionEndpointsTests(CustomWebApplicationFactory factory) : IntegrationTestBase(factory)
{
    [Theory]
    [InlineData(null)]
    [InlineData(2)]
    public async Task Refresh_AfterWorkspaceRemoval_UpdatesTheResponseAndCookieTogether(int? replacementId)
    {
        await using (var context = GetDbContext())
        {
            var user = await context.Users.SingleAsync(u => u.Id == DefaultUserId);
            user.ActiveWorkspaceId = replacementId;
            user.Email = "current@example.test";
            context.WorkspaceUsers.RemoveRange(await context.WorkspaceUsers.Where(m => m.UserId == DefaultUserId).ToListAsync());
            if (replacementId is int id)
            {
                context.Workspaces.Add(new Workspace { Id = id, Name = "Replacement", HasCompletedWelcome = true });
                context.WorkspaceUsers.Add(new WorkspaceUser { UserId = DefaultUserId, WorkspaceId = id, WorkspaceRole = WorkspaceRole.Normal });
            }
            await context.SaveChangesAsync();
        }
        // The client's original claims still name workspace 1 and its old administrator role.
        var response = await Client.GetAsync("/api/auth/me");
        response.EnsureSuccessStatusCode();
        var session = (await DeserializeResponseAsync<CurrentUserResponse>(response))!;
        Assert.Equal(replacementId, session.WorkspaceId);
        Assert.Equal("current@example.test", session.Email);
        Assert.Equal(WorkspaceRole.Normal, session.WorkspaceRole);
        Assert.False(session.IsWorkspaceAdmin);
        Assert.True(response.Headers.CacheControl!.NoStore);
        var cookieName = Factory.Services.GetRequiredService<IOptions<AuthenticationSettings>>().Value.Cookie.Name;
        var cookie = SetCookieHeaderValue.ParseList(response.Headers.GetValues("Set-Cookie").ToList()).Single(c => c.Name == cookieName);
        var principal = Factory.Services.GetRequiredService<ITokenService>().ValidateAppToken(cookie.Value.ToString());
        Assert.NotNull(principal);
        Assert.Equal(replacementId?.ToString(), principal.FindFirst(ClaimNames.WorkspaceId)?.Value);
        Assert.Equal("Normal", principal.FindFirst(ClaimNames.WorkspaceRole)?.Value);
        if (replacementId is null)
        {
            Assert.Null(session.ActiveWorkspace);
            Assert.Empty(session.Workspaces);
            var protectedRequest = await Client.GetAsync("/api/collections");
            Assert.Equal(HttpStatusCode.Unauthorized, protectedRequest.StatusCode);
            Assert.Contains("NO_ACTIVE_WORKSPACES", await protectedRequest.Content.ReadAsStringAsync());
        }
        else Assert.Equal("Replacement", session.ActiveWorkspace!.WorkspaceName);
    }

    [Fact]
    public async Task DeletedAccount_CannotBeRecreatedFromOldClaims()
    {
        await using var context = GetDbContext();
        context.Users.Remove(await context.Users.SingleAsync(u => u.Id == DefaultUserId));
        await context.SaveChangesAsync();
        var response = await Client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(response.Headers.Contains("Set-Cookie"));
    }
}
