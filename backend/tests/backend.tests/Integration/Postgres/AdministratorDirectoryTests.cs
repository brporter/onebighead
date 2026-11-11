using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Administration;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class AdministratorDirectoryTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private static readonly DateTime Created = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private AdministratorDirectory Directory() => new(fixture.CreateContextFactory());

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var context = fixture.CreateContext();
        context.Workspaces.AddRange(new Workspace { Id = 1, Name = "Zeta", CreatedAt = Created },
            new Workspace { Id = 2, Name = "Alpha", CreatedAt = Created },
            new Workspace { Id = 3, Name = "Alpha", CreatedAt = Created });
        context.Users.AddRange(
            new User { Id = 1, ActiveWorkspaceId = 1, Email = "z.reader@example.test", IdentityProvider = IdentityProvider.Google, IsSystemAdministrator = true, CreatedAt = Created },
            new User { Id = 2, ActiveWorkspaceId = 2, Email = "amy@EXAMPLE.test", CreatedAt = Created },
            new User { Id = 3, ActiveWorkspaceId = 2, Email = "pat%test@example.test", CreatedAt = Created },
            new User { Id = 4, ActiveWorkspaceId = 1, Email = "tag_name@example.test", CreatedAt = Created });
        context.WorkspaceUsers.AddRange(new WorkspaceUser { UserId = 1, WorkspaceId = 1 },
            new WorkspaceUser { UserId = 1, WorkspaceId = 2 }, new WorkspaceUser { UserId = 2, WorkspaceId = 2 });
        context.Collections.AddRange(new Collection { Id = 1, WorkspaceId = 1, Name = "Books", Slug = "books" },
            new Collection { Id = 2, WorkspaceId = 1, Name = "Records", Slug = "records" },
            new Collection { Id = 3, WorkspaceId = 2, Name = "Cameras", Slug = "cameras" });
        context.Items.AddRange(new Item { WorkspaceId = 1, CollectionId = 1, Name = "Book one", Images = [new("/one", "One"), new("/two", "Two")] },
            new Item { WorkspaceId = 1, CollectionId = 1, Name = "Book two", Images = [] },
            new Item { WorkspaceId = 2, CollectionId = 3, Name = "Camera", Images = [new("/three", "Three")] });
        await context.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Workspaces_ReturnSortedIndependentCounts_IncludingEmptyWorkspaces()
    {
        var rows = await Directory().GetWorkspacesAsync();
        Assert.Equal(new[] { 2, 3, 1 }, rows.Select(row => row.WorkspaceId));
        var byId = rows.ToDictionary(row => row.WorkspaceId);
        Assert.Equal((1, 2, 2, 2), Counts(byId[1]));
        Assert.Equal((2, 1, 1, 1), Counts(byId[2]));
        Assert.Equal((0, 0, 0, 0), Counts(byId[3]));
        Assert.All(rows, row => Assert.Equal(Created, row.CreatedAt));
    }

    [Theory]
    [InlineData(null, new[] { 2, 3, 4, 1 })]
    [InlineData("", new[] { 2, 3, 4, 1 })]
    [InlineData("  ", new[] { 2, 3, 4, 1 })]
    [InlineData(" aMY@eXAMPLE ", new[] { 2 })]
    [InlineData("%", new[] { 3 })]
    [InlineData("_", new[] { 4 })]
    [InlineData("missing", new int[] { })]
    public async Task UserSearch_IsTrimmedCaseInsensitiveAndTreatsWildcardsLiterally(string? search, int[] expected)
    {
        var users = await Directory().GetUsersAsync(search);
        Assert.Equal(expected, users.Select(user => user.UserId));
        Assert.All(users, user => Assert.Equal(Created, user.CreatedAt));
    }

    [Fact]
    public async Task UserSummary_UsesTheActiveWorkspaceAndRetainsAccountMetadata()
    {
        var user = Assert.Single(await Directory().GetUsersAsync("z.reader"));
        Assert.Equal(1, user.WorkspaceId);
        Assert.Equal("Zeta", user.WorkspaceName);
        Assert.Equal("z.reader@example.test", user.Email);
        Assert.Equal("Google", user.IdentityProvider);
        Assert.True(user.IsSystemAdministrator);
    }

    [Fact]
    public async Task EmptyDirectory_ReturnsEmptyLists()
    {
        await fixture.ResetAsync();
        Assert.Empty(await Directory().GetWorkspacesAsync());
        Assert.Empty(await Directory().GetUsersAsync(null));
    }

    private static (int, int, int, int) Counts(WorkspaceSummaryResponse response) =>
        (response.UserCount, response.CollectionCount, response.ItemCount, response.ImageCount);
}
