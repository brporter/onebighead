using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Net.Http.Headers;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

public class AccountEndpointsTests(CustomWebApplicationFactory factory) : IntegrationTestBase(factory)
{
    public override async Task InitializeAsync()
    {
        await using var db = GetDbContext();
        await db.Database.EnsureDeletedAsync();
        await base.InitializeAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AccountWithoutActiveWorkspace_CanPreviewAndDelete(bool softDeleted)
    {
        await using (var db = GetDbContext())
        {
            db.WorkspaceUsers.RemoveRange(await db.WorkspaceUsers.Where(m => m.UserId == DefaultUserId).ToListAsync());
            var user = await db.Users.SingleAsync(u => u.Id == DefaultUserId);
            user.ActiveWorkspaceId = null;
            user.IsDeleted = softDeleted;
            await db.SaveChangesAsync();
        }
        var preview = await Client.GetAsync("/api/users/me/deletion-info");
        preview.EnsureSuccessStatusCode();
        Assert.True((await DeserializeResponseAsync<UserDeletionInfoResponse>(preview))!.CanDeleteImmediately);
        var response = await Delete(new() { ConfirmEmail = DefaultEmail });
        response.EnsureSuccessStatusCode();
        Assert.True((await DeserializeResponseAsync<DeleteUserResponse>(response))!.Success);
        var cookie = Assert.Single(SetCookieHeaderValue.ParseList(response.Headers.GetValues("Set-Cookie").ToList()));
        Assert.Equal(string.Empty, cookie.Value.ToString());
        Assert.True(cookie.Expires < DateTimeOffset.UtcNow);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Client.GetAsync("/api/auth/me")).StatusCode);
        await using var check = GetDbContext();
        Assert.False(await check.Users.AnyAsync(u => u.Id == DefaultUserId));
        Assert.True(await check.Users.AnyAsync(u => u.Id == DefaultNormalUserId));
        Assert.Single(await check.Collections.ToListAsync());
    }

    [Fact]
    public async Task TransferAndDelete_UsesRegisteredModulesAndPreservesWorkspaceForSuccessor()
    {
        var preview = await DeserializeResponseAsync<UserDeletionInfoResponse>(await Client.GetAsync("/api/users/me/deletion-info"));
        Assert.Equal(DefaultNormalUserId, Assert.Single(Assert.Single(preview!.WorkspaceMemberships).OtherUsers).UserId);
        var result = await Delete(new()
        {
            ConfirmEmail = DefaultEmail,
            WorkspaceActions = [new() { WorkspaceId = DefaultWorkspaceId, Action = WorkspaceActionType.Transfer, TransferToUserId = DefaultNormalUserId }]
        });
        result.EnsureSuccessStatusCode();
        await using var check = GetDbContext();
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, (await check.WorkspaceUsers.SingleAsync()).WorkspaceRole);
        Assert.False((await check.Workspaces.SingleAsync()).IsDeleted);
    }

    [Theory]
    [InlineData("wrong-email")]
    [InlineData("duplicate")]
    [InlineData("self")]
    [InlineData("null-action")]
    public async Task InvalidRequest_DoesNotDeleteOrClearCookie(string scenario)
    {
        var request = new DeleteUserRequest { ConfirmEmail = DefaultEmail,
            WorkspaceActions = [new() { WorkspaceId = DefaultWorkspaceId, Action = WorkspaceActionType.Transfer, TransferToUserId = DefaultNormalUserId }] };
        if (scenario == "wrong-email") request.ConfirmEmail = "other@example.test";
        if (scenario == "duplicate") request.WorkspaceActions.Add(request.WorkspaceActions[0]);
        if (scenario == "self") request.WorkspaceActions[0].TransferToUserId = DefaultUserId;
        if (scenario == "null-action") request.WorkspaceActions.Add(null!);
        var response = await Delete(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(response.Headers.Contains("Set-Cookie"));
        await using var check = GetDbContext();
        Assert.Equal(2, await check.Users.CountAsync());
        Assert.Equal(WorkspaceRole.Normal, (await check.WorkspaceUsers.SingleAsync(m => m.UserId == DefaultNormalUserId)).WorkspaceRole);
    }

    [Fact]
    public async Task AnonymousRequests_CannotReadOrDeleteAccounts()
    {
        using var anonymous = CreateAnonymousClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/users/me/deletion-info")).StatusCode);
        using var request = new HttpRequestMessage(HttpMethod.Delete, "/api/users/me") { Content = JsonContent.Create(new DeleteUserRequest { ConfirmEmail = DefaultEmail }) };
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.SendAsync(request)).StatusCode);
    }

    private Task<HttpResponseMessage> Delete(DeleteUserRequest request) => Client.SendAsync(new HttpRequestMessage(HttpMethod.Delete, "/api/users/me")
    {
        Content = JsonContent.Create(request, options: JsonOptions)
    });
}
