using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

public class WorkspaceRestorationControllerTests(CustomWebApplicationFactory factory) : IntegrationTestBase(factory)
{
    protected override async Task SeedAdditionalDataAsync()
    {
        await using var context = GetDbContext();
        var current = await context.Workspaces.SingleAsync(w => w.Id == 1);
        current.IsDeleted = true;
        var archive = await context.Workspaces.FindAsync(2);
        if (archive is null)
        {
            archive = new Workspace { Id = 2, Name = "Archive" };
            context.Workspaces.Add(archive);
            context.WorkspaceUsers.Add(new WorkspaceUser { UserId = 1, WorkspaceId = 2, WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
        }
        archive.IsDeleted = true;
        archive.DeletedAt = DateTime.UtcNow;
        archive.DeletedByUserId = 1;
        (await context.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId = 1;
        await context.SaveChangesAsync();
    }

    [Fact]
    public async Task BatchRoute_RecoversFromInactiveWorkspace_AndCookieContainsCommittedContext()
    {
        using var response = await Client.PostAsJsonAsync("/api/workspaces/restore", new { workspaceIds = new[] { 2 } });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<RestoreWorkspacesResponse>();
        Assert.Equal(2, result!.ActiveWorkspaceId);
        Assert.Equal(new[] { 2 }, result.RestoredWorkspaceIds);

        var cookieName = Factory.Services.GetRequiredService<IOptions<AuthenticationSettings>>().Value.Cookie.Name;
        var cookie = Assert.Single(response.Headers.GetValues("Set-Cookie"), value => value.StartsWith(cookieName + "=", StringComparison.Ordinal));
        var token = cookie[(cookieName.Length + 1)..cookie.IndexOf(';')];
        var principal = Factory.Services.GetRequiredService<ITokenService>().ValidateAppToken(token);
        Assert.NotNull(principal);
        Assert.Equal("1", principal.FindFirstValue(ClaimTypes.NameIdentifier));
        Assert.Equal("2", principal.FindFirstValue(ClaimNames.WorkspaceId));
        Assert.Equal("WorkspaceAdmin", principal.FindFirstValue(ClaimNames.WorkspaceRole));

        await using var context = GetDbContext();
        Assert.Equal(2, (await context.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
        Assert.False((await context.Workspaces.SingleAsync(w => w.Id == 2)).IsDeleted);
    }

    [Fact]
    public async Task SingleRoute_RestoresWithoutSwitchingTheSession()
    {
        using var response = await Client.PostAsync("/api/workspaces/2/restore", null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<RestoreWorkspaceResponse>();
        Assert.Equal(2, result!.WorkspaceId);
        Assert.Equal("Archive", result.Name);
        Assert.False(response.Headers.Contains("Set-Cookie"));
        await using var context = GetDbContext();
        Assert.Equal(1, (await context.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
    }

    [Fact]
    public async Task BatchRoute_RejectsLaterUnauthorizedWorkspaceWithoutPartialRestoration()
    {
        using var response = await Client.PostAsJsonAsync("/api/workspaces/restore", new { workspaceIds = new[] { 2, 99 } });
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(response.Headers.Contains("Set-Cookie"));
        await using var context = GetDbContext();
        Assert.True((await context.Workspaces.SingleAsync(w => w.Id == 2)).IsDeleted);
        Assert.Equal(1, (await context.Users.SingleAsync(u => u.Id == 1)).ActiveWorkspaceId);
    }

    [Theory]
    [InlineData("/api/workspaces/restore")]
    [InlineData("/api/workspaces/2/restore")]
    public async Task RecoveryRoutes_StillRequireAuthentication(string route)
    {
        using var anonymous = CreateAnonymousClient();
        using var response = await anonymous.PostAsJsonAsync(route, new { workspaceIds = new[] { 2 } });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
