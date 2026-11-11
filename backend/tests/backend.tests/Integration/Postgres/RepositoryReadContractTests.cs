using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
public class RepositoryReadContractTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    public Task InitializeAsync() => fixture.ResetAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task WorkspaceStats_CountsOnlyTheRequestedWorkspaceAndReturnsZeroForMissingWorkspaces()
    {
        await using (var context = fixture.CreateContext())
        {
            context.Workspaces.AddRange(new Workspace { Id = 1, Name = "First" }, new Workspace { Id = 2, Name = "Second" });
            context.Collections.AddRange(new Collection { Id = 1, WorkspaceId = 1, Name = "First", Slug = "first" },
                new Collection { Id = 2, WorkspaceId = 2, Name = "Second", Slug = "second" });
            context.Categories.AddRange(new Category { Id = 1, WorkspaceId = 1, CollectionId = 1, Name = "First" },
                new Category { Id = 2, WorkspaceId = 2, CollectionId = 2, Name = "Second" });
            context.Items.AddRange(new Item { WorkspaceId = 1, CollectionId = 1, Name = "First" },
                new Item { WorkspaceId = 1, CollectionId = 1, Name = "Another" },
                new Item { WorkspaceId = 2, CollectionId = 2, Name = "Second" });
            context.StoredImages.AddRange(new StoredImage { Id = Guid.NewGuid(), WorkspaceId = 1 },
                new StoredImage { Id = Guid.NewGuid(), WorkspaceId = 2 });
            await context.SaveChangesAsync();
        }

        var repository = new WorkspaceRepository(fixture.CreateContextFactory());
        var first = await repository.GetStatsAsync(1);
        Assert.Equal((1, 2, 1, 1), (first.CollectionCount, first.ItemCount, first.CategoryCount, first.ImageCount));
        var missing = await repository.GetStatsAsync(99);
        Assert.Equal((0, 0, 0, 0), (missing.CollectionCount, missing.ItemCount, missing.CategoryCount, missing.ImageCount));
    }

    [Fact]
    public async Task AdminMemberships_IncludeDeletedWorkspacesButExcludeOtherUsersAndNonAdminRoles()
    {
        await using (var context = fixture.CreateContext())
        {
            context.Workspaces.AddRange(new Workspace { Id = 1, Name = "Active" },
                new Workspace { Id = 2, Name = "Deleted", IsDeleted = true }, new Workspace { Id = 3, Name = "Shared" });
            context.Users.AddRange(new User { Id = 1, Email = "first@example.com" }, new User { Id = 2, Email = "second@example.com" });
            context.WorkspaceUsers.AddRange(
                new WorkspaceUser { UserId = 1, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
                new WorkspaceUser { UserId = 1, WorkspaceId = 2, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
                new WorkspaceUser { UserId = 1, WorkspaceId = 3, WorkspaceRole = WorkspaceRole.Normal },
                new WorkspaceUser { UserId = 2, WorkspaceId = 3, WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
            await context.SaveChangesAsync();
        }

        var repository = new WorkspaceUserRepository(fixture.CreateContextFactory());
        var memberships = (await repository.GetAdminMembershipsIncludingDeletedAsync(1)).OrderBy(m => m.WorkspaceId).ToArray();
        Assert.Equal(new[] { 1, 2 }, memberships.Select(m => m.WorkspaceId));
        Assert.All(memberships, m => Assert.Equal(1, m.UserId));
        Assert.Equal("Active", memberships[0].Workspace.Name);
        Assert.False(memberships[0].Workspace.IsDeleted);
        Assert.Equal("Deleted", memberships[1].Workspace.Name);
        Assert.True(memberships[1].Workspace.IsDeleted);
        Assert.Empty(await repository.GetAdminMembershipsIncludingDeletedAsync(99));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task AccountCreation_RollsBackWorkspaceUserAndMembershipWhenAnySaveFails(int saveToFail)
    {
        var failure = new InvalidOperationException("Injected persistence failure");
        var options = new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString)
            .AddInterceptors(new FailingSave(saveToFail, failure)).Options;
        var repository = new UserRepository(new TestDbContextFactory(options));

        Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() =>
            repository.CreateWithNewWorkspaceAsync("new@example.com", IdentityProvider.Google, "new-user")));

        await using var context = fixture.CreateContext();
        Assert.Empty(await context.Workspaces.ToListAsync());
        Assert.Empty(await context.Users.ToListAsync());
        Assert.Empty(await context.WorkspaceUsers.ToListAsync());
    }

    [Fact]
    public async Task Suggestions_RetainUsedNamesWithoutDuplicatingCaseVariantsOrChangingOtherCollections()
    {
        await using (var context = fixture.CreateContext())
        {
            context.Workspaces.Add(new Workspace { Id = 1, Name = "Workspace" });
            context.Collections.AddRange(new Collection { Id = 1, WorkspaceId = 1, Name = "First", Slug = "first" },
                new Collection { Id = 2, WorkspaceId = 1, Name = "Second", Slug = "second" });
            context.Items.Add(new Item { WorkspaceId = 1, CollectionId = 1, Name = "Book",
                Properties = [new ItemProperty(" Publication ", " AUTHOR ", "Writer")] });
            context.PropertySuggestions.AddRange(
                new PropertySuggestion { WorkspaceId = 1, CollectionId = 1, Type = PropertySuggestionType.Name, Value = "Author" },
                new PropertySuggestion { WorkspaceId = 1, CollectionId = 1, Type = PropertySuggestionType.Name, Value = "Unused" },
                new PropertySuggestion { WorkspaceId = 1, CollectionId = 2, Type = PropertySuggestionType.Name, Value = "Other" });
            await context.SaveChangesAsync();
        }
        var repository = new PropertySuggestionRepository(fixture.CreateContextFactory());
        await repository.SyncSuggestionsAsync(1, 1, [], []);
        await repository.SyncSuggestionsAsync(1, 1, [], []);
        Assert.Equal(new[] { "Author" }, await repository.GetNamesAsync(1, 1));
        Assert.Equal(new[] { "Publication" }, await repository.GetCategoriesAsync(1, 1));
        Assert.Equal(new[] { "Other" }, await repository.GetNamesAsync(2, 1));
    }

    private sealed class FailingSave(int saveToFail, Exception failure) : SaveChangesInterceptor
    {
        private int _saves;
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (++_saves == saveToFail) throw failure;
            return ValueTask.FromResult(result);
        }
    }
}
