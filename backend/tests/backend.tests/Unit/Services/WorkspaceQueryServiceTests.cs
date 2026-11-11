using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Tests.Unit.Services;

[Trait("Category", "Unit")]
public class WorkspaceQueryServiceTests : IAsyncLifetime
{
    private readonly TestDbContextFactory _factory = new(new DbContextOptionsBuilder<AppDbContext>()
        .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);

    public async Task InitializeAsync()
    {
        await using var context = _factory.CreateDbContext();
        context.Workspaces.AddRange(Enumerable.Range(1, 4).Select(id => new Workspace { Id = id, Name = $"Workspace {id}", IsDeleted = id == 2 }));
        context.Users.AddRange(Enumerable.Range(1, 4).Select(id => new User { Id = id, ActiveWorkspaceId = 1, IsDeleted = id == 2 }));
        context.WorkspaceUsers.AddRange(
            new WorkspaceUser { UserId = 1, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
            new WorkspaceUser { UserId = 2, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.Normal },
            new WorkspaceUser { UserId = 3, WorkspaceId = 3, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
            new WorkspaceUser { UserId = 4, WorkspaceId = 2, WorkspaceRole = WorkspaceRole.Normal });
        context.Collections.AddRange(new Collection { Id = 1, WorkspaceId = 1 }, new Collection { Id = 2, WorkspaceId = 1 }, new Collection { Id = 3, WorkspaceId = 3 });
        context.Categories.AddRange(new Category { Id = 1, CollectionId = 1, WorkspaceId = 1 }, new Category { Id = 2, CollectionId = 3, WorkspaceId = 3 });
        context.Items.AddRange(new Item { Id = 1, CollectionId = 1, WorkspaceId = 1 }, new Item { Id = 2, CollectionId = 2, WorkspaceId = 1 }, new Item { Id = 3, CollectionId = 3, WorkspaceId = 3 });
        context.StoredImages.AddRange(new StoredImage { Id = Guid.NewGuid(), WorkspaceId = 1 }, new StoredImage { Id = Guid.NewGuid(), WorkspaceId = 3 });
        await context.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData(1, false)]
    [InlineData(2, true)]
    [InlineData(99, true)]
    public async Task AccessChecks_TreatDeletedOrMissingEntitiesAsUnavailable(int id, bool unavailable)
    {
        var service = new WorkspaceAccessService(_factory);
        Assert.Equal(unavailable, await service.IsUserDeletedAsync(id));
        Assert.Equal(unavailable, await service.IsWorkspaceDeletedAsync(id));
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(3, true)]
    [InlineData(4, false)]
    [InlineData(99, false)]
    public async Task ActiveMemberships_AreScopedToTheUserAndExcludeDeletedWorkspaces(int id, bool available)
    {
        Assert.Equal(available, await new WorkspaceAccessService(_factory).HasUserAnyActiveWorkspaceAsync(id));
    }

    [Fact]
    public async Task Summary_CountsOnlyRequestedWorkspaceResourcesAndMembershipRoles()
    {
        var summary = await new WorkspaceSummaryService(_factory).GetWorkspaceStatsAsync(1);
        Assert.NotNull(summary);
        Assert.Equal(1, summary.WorkspaceId);
        Assert.Equal("Workspace 1", summary.WorkspaceName);
        Assert.Equal(2, summary.CollectionCount);
        Assert.Equal(1, summary.CategoryCount);
        Assert.Equal(2, summary.ItemCount);
        Assert.Equal(1, summary.ImageCount);
        Assert.Equal(2, summary.UserCount);
        Assert.Equal(1, summary.AdminCount);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(99)]
    public async Task Summary_RejectsDeletedOrMissingWorkspaces(int id) =>
        Assert.Null(await new WorkspaceSummaryService(_factory).GetWorkspaceStatsAsync(id));

    [Fact]
    public async Task Summary_HandlesAnEmptyWorkspace()
    {
        var summary = await new WorkspaceSummaryService(_factory).GetWorkspaceStatsAsync(4);
        Assert.NotNull(summary);
        Assert.Equal(0, summary.CollectionCount);
        Assert.Equal(0, summary.CategoryCount);
        Assert.Equal(0, summary.ItemCount);
        Assert.Equal(0, summary.ImageCount);
        Assert.Equal(0, summary.UserCount);
        Assert.Equal(0, summary.AdminCount);
    }
}
