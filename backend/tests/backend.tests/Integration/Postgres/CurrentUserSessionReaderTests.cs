using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class CurrentUserSessionReaderTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    public Task InitializeAsync() => fixture.ResetAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task MissingAccount_HasNoSession() =>
        Assert.Null(await new CurrentUserSessionReader(fixture.CreateContextFactory()).ReadAsync(42));

    [Theory]
    [InlineData(null, false)]
    [InlineData(1, false)]
    [InlineData(2, false)]
    [InlineData(3, false)]
    [InlineData(1, true)]
    public async Task Session_UsesOnlyCurrentActiveMemberships(int? activeId, bool deletedUser)
    {
        await using (var context = fixture.CreateContext())
        {
            context.Workspaces.AddRange(new Workspace { Id = 1, Name = "Reading room", HasCompletedWelcome = true, Slug = "books" },
                new Workspace { Id = 2, Name = "Deleted", IsDeleted = true }, new Workspace { Id = 3, Name = "Not a member" },
                new Workspace { Id = 4, Name = "Second" });
            context.Users.Add(new User { Id = 1, ActiveWorkspaceId = activeId, Email = "current@example.test",
                IsSystemAdministrator = true, IsDeleted = deletedUser, AcceptedTermsAt = DateTime.UtcNow });
            context.WorkspaceUsers.AddRange(new WorkspaceUser { UserId = 1, WorkspaceId = 4 },
                new WorkspaceUser { UserId = 1, WorkspaceId = 2 },
                new WorkspaceUser { UserId = 1, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
            await context.SaveChangesAsync();
        }
        var session = await new CurrentUserSessionReader(fixture.CreateContextFactory()).ReadAsync(1);
        Assert.NotNull(session);
        var response = session.Response;
        Assert.Equal(1, response.UserId);
        Assert.Equal("current@example.test", response.Email);
        Assert.True(response.HasAcceptedTerms);
        Assert.Equal(!deletedUser, response.IsSystemAdministrator);
        Assert.Equal(new[] { 1, 4 }, response.Workspaces.Select(w => w.WorkspaceId));
        Assert.Equal(activeId == 1 ? 1 : (int?)null, response.WorkspaceId);
        Assert.Equal(response.WorkspaceId, session.User.ActiveWorkspaceId);
        Assert.Equal(activeId == 1 ? "Reading room" : "", response.WorkspaceName);
        Assert.Equal(activeId == 1, response.HasCompletedWelcome);
        Assert.Equal(activeId == 1, response.IsWorkspaceAdmin);
        Assert.Equal(activeId == 1 ? WorkspaceRole.WorkspaceAdmin : WorkspaceRole.Normal, response.WorkspaceRole);
        Assert.Equal(activeId == 1 ? "books" : null, response.ActiveWorkspace?.Slug);
        // Reading/sanitizing a cookie never silently changes the stored active choice.
        await using var check = fixture.CreateContext();
        Assert.Equal(activeId, (await check.Users.SingleAsync()).ActiveWorkspaceId);
    }

    [Fact]
    public async Task WorkspaceLessAccount_PersistsAndHasAnExplicitEmptySession()
    {
        await using (var context = fixture.CreateContext())
        {
            context.Users.Add(new User { Id = 1, Email = "remaining@example.test" });
            await context.SaveChangesAsync();
        }
        var session = await new CurrentUserSessionReader(fixture.CreateContextFactory()).ReadAsync(1);
        Assert.NotNull(session);
        Assert.Null(session.Response.ActiveWorkspace);
        Assert.Null(session.Response.WorkspaceId);
        Assert.Empty(session.Response.Workspaces);
        Assert.False(session.Response.HasAcceptedTerms);
        Assert.False(session.Response.IsSystemAdministrator);
    }
}
