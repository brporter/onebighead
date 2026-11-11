using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Tests.Integration.Postgres;

public partial class WorkspaceWelcomeTests
{
    [Theory]
    [InlineData(null, "")]
    [InlineData("  Signed copies  ", "Signed copies")]
    public async Task Welcome_CommitsItsCollectionGraphCompletionAndCounterTogether(string? description, string expected)
    {
        await SeedWelcomeTheme();
        var request = CollectionWelcome();
        request.Collection!.Description = description;
        request.Collection.HeroImageUrl = "/api/images/cover";
        var response = (await Welcome().CompleteAsync(1, 1, request)).Workspace!;
        await using var db = fixture.CreateContext();
        var collection = await db.Collections.SingleAsync();
        Assert.Equal(collection.Id, response.CollectionId);
        Assert.Equal("Books", response.CollectionName);
        Assert.Equal("Library", response.WorkspaceName);
        Assert.True(response.HasCompletedWelcome);
        Assert.Equal(1, collection.WorkspaceId);
        Assert.Equal("books", collection.Slug);
        Assert.Equal(expected, collection.Description);
        Assert.Equal("/api/images/cover", collection.HeroImageUrl);
        Assert.Equal(Visibility.Private, collection.Visibility);
        Assert.InRange(collection.CreatedAt, DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddMinutes(1));
        Assert.Equal(collection.Id, (await db.Workspaces.SingleAsync(w => w.Id == 1)).WelcomeCollectionId);
        var categories = await db.Categories.ToListAsync();
        Assert.Equal(3, categories.Count);
        Assert.All(categories, category => Assert.Equal(collection.Id, category.CollectionId));
        Assert.Equal(categories.Single(c => c.Name == "Authors").Id, categories.Single(c => c.Name == "Modern").ParentCategoryId);
        Assert.Equal(10, (await db.CollectionItemTemplates.SingleAsync()).ItemTemplateId);
        var count = await db.WorkspaceStatistics.SingleAsync();
        Assert.Equal(StatisticType.CollectionCount, count.StatisticType);
        Assert.Equal(1, count.Value);
    }

    [Theory]
    [InlineData("missing-name")]
    [InlineData("blank-name")]
    [InlineData("long-name")]
    [InlineData("long-description")]
    [InlineData("long-image")]
    public async Task Welcome_ValidatesNestedCollectionBeforeWriting(string invalid)
    {
        var request = CollectionWelcome();
        switch (invalid)
        {
            case "missing-name": request.Collection!.Name = null!; break;
            case "blank-name": request.Collection!.Name = "  "; break;
            case "long-name": request.Collection!.Name = new string('a', 201); break;
            case "long-description": request.Collection!.Description = new string('a', 1001); break;
            case "long-image": request.Collection!.HeroImageUrl = new string('a', 501); break;
        }
        var result = await Welcome().CompleteAsync(1, 1, request);
        Assert.Equal(WorkspaceWelcomeStatus.Invalid, result.Status);
        Assert.Contains("collection name", result.Error);
        await AssertOriginalWorkspace();
        await AssertNoWelcomeCollection();
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("cycle")]
    [InlineData("private-template")]
    public async Task Welcome_RejectsUnavailableOrInvalidThemesWithoutPartialCompletion(string invalid)
    {
        if (invalid != "missing")
        {
            await SeedWelcomeTheme();
            await using var db = fixture.CreateContext();
            if (invalid == "cycle")
                await db.CollectionThemeCategories.Where(c => c.Name == "Authors").ExecuteUpdateAsync(s => s.SetProperty(c => c.ParentName, "Modern"));
            else
                await db.ItemTemplates.Where(t => t.Id == 10).ExecuteUpdateAsync(s => s.SetProperty(t => t.WorkspaceId, 4));
        }
        var result = await Welcome().CompleteAsync(1, 1, CollectionWelcome());
        Assert.Equal(WorkspaceWelcomeStatus.Invalid, result.Status);
        Assert.NotEmpty(result.Error!);
        await AssertOriginalWorkspace();
        await AssertNoWelcomeCollection();
    }

    [Fact]
    public async Task LostWelcomeResponse_CanBeRecoveredByANewServiceWithoutRepeatingCreationOrRenaming()
    {
        await SeedWelcomeTheme();
        var first = (await Welcome().CompleteAsync(1, 1, CollectionWelcome())).Workspace!;
        await using var db = fixture.CreateContext();
        await db.Workspaces.Where(w => w.Id == 1).ExecuteUpdateAsync(s => s.SetProperty(w => w.Name, "Updated library"));
        await db.Collections.Where(c => c.Id == first.CollectionId).ExecuteUpdateAsync(s => s.SetProperty(c => c.Name, "Updated books"));
        var noWrite = new BeforeMembershipSave(() => throw new InvalidOperationException("Replay must be read-only"));
        var staleDraft = CollectionWelcome();
        staleDraft.Collection!.ThemeId = 999;
        var replay = (await Welcome(noWrite).CompleteAsync(3, 1, staleDraft)).Workspace!;
        Assert.Equal(first.CollectionId, replay.CollectionId);
        Assert.Equal("Updated books", replay.CollectionName);
        Assert.Equal("Updated library", replay.WorkspaceName);
        Assert.Equal(1, await db.Collections.CountAsync());
        Assert.Equal(1, (await db.WorkspaceStatistics.SingleAsync()).Value);
    }

    [Fact]
    public async Task PreviouslySkippedWelcome_DoesNotCreateACollectionOnRetry()
    {
        await Welcome().CompleteAsync(1, 1, new());
        var replay = (await Welcome().CompleteAsync(1, 1, CollectionWelcome())).Workspace!;
        Assert.Null(replay.CollectionId);
        Assert.Null(replay.CollectionName);
        Assert.True(replay.HasCompletedWelcome);
        await AssertNoWelcomeCollection();
    }

    [Fact]
    public async Task DeletedInitialCollection_LeavesWelcomeCompleteAndDoesNotRecreateIt()
    {
        await SeedWelcomeTheme();
        await Welcome().CompleteAsync(1, 1, CollectionWelcome());
        await using var db = fixture.CreateContext();
        await db.Categories.ExecuteDeleteAsync();
        await db.Collections.ExecuteDeleteAsync();
        Assert.Null((await db.Workspaces.SingleAsync(w => w.Id == 1)).WelcomeCollectionId);
        var replay = (await Welcome().CompleteAsync(1, 1, CollectionWelcome())).Workspace!;
        Assert.True(replay.HasCompletedWelcome);
        Assert.Null(replay.CollectionId);
        Assert.Null(replay.CollectionName);
        Assert.Empty(await db.Collections.ToListAsync());
    }

    [Fact]
    public async Task WelcomeResponse_DoesNotExposeAnInitialCollectionOutsideItsWorkspace()
    {
        await using var db = fixture.CreateContext();
        var foreign = new OneBigHead.Server.Models.Collection { WorkspaceId = 2, Name = "Private collection" };
        db.Collections.Add(foreign);
        await db.SaveChangesAsync();
        await db.Workspaces.Where(w => w.Id == 1).ExecuteUpdateAsync(s => s.SetProperty(w => w.HasCompletedWelcome, true).SetProperty(w => w.WelcomeCollectionId, foreign.Id));
        var response = (await Welcome().CompleteAsync(1, 1, new())).Workspace!;
        Assert.Null(response.CollectionId);
        Assert.Null(response.CollectionName);
    }

    [Fact]
    public async Task ConcurrentWelcomeCollections_CommitOnlyOneGraphAndRecoverTheWinningResult()
    {
        await SeedWelcomeTheme();
        var service = Welcome(new SynchronizedSaves());
        var results = await Task.WhenAll(service.CompleteAsync(1, 1, CollectionWelcome()), service.CompleteAsync(3, 1, CollectionWelcome()))
            .WaitAsync(TimeSpan.FromSeconds(20));
        var completed = Assert.Single(results, result => result.Status == WorkspaceWelcomeStatus.Completed).Workspace!;
        Assert.Single(results, result => result.Status == WorkspaceWelcomeStatus.Conflict);
        Assert.Equal(completed.CollectionId, (await Welcome().CompleteAsync(1, 1, CollectionWelcome())).Workspace!.CollectionId);
        await using var db = fixture.CreateContext();
        Assert.Equal(1, await db.Collections.CountAsync());
        Assert.Equal(3, await db.Categories.CountAsync());
        Assert.Equal(1, (await db.WorkspaceStatistics.SingleAsync()).Value);
    }

    [Fact]
    public async Task FailedReceiptSave_RollsBackTheAlreadySavedGraphAndCounter()
    {
        await SeedWelcomeTheme();
        var failure = new InvalidOperationException("Receipt save unavailable");
        Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Welcome(new FailSecondSave(failure)).CompleteAsync(1, 1, CollectionWelcome())));
        await AssertOriginalWorkspace();
        await AssertNoWelcomeCollection();
    }

    [Fact]
    public async Task WelcomeEndpoint_ValidatesNestedInputAndReturnsTheOriginalCollectionOnReplay()
    {
        await SeedWelcomeTheme();
        await using var factory = new MembershipWebApplicationFactory(fixture.ConnectionString);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, "1");
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, "1");
        var invalid = CollectionWelcome();
        invalid.Collection!.Name = "";
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/auth/complete-welcome", invalid)).StatusCode);
        var response = await client.PostAsJsonAsync("/api/auth/complete-welcome", CollectionWelcome());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var completed = (await response.Content.ReadFromJsonAsync<CompleteWelcomeResponse>())!;
        Assert.NotNull(completed.CollectionId);
        var replay = await client.PostAsJsonAsync("/api/auth/complete-welcome", CollectionWelcome());
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        Assert.Equal(completed.CollectionId, (await replay.Content.ReadFromJsonAsync<CompleteWelcomeResponse>())!.CollectionId);
    }

    private async Task SeedWelcomeTheme()
    {
        await using var db = fixture.CreateContext();
        db.ItemTemplates.Add(new ItemTemplate { Id = 10, Name = "Book", TemplateKey = Guid.NewGuid() });
        db.CollectionThemes.Add(new CollectionTheme
        {
            Id = 10, Name = "Books", ThemeTemplates = [new() { ItemTemplateId = 10 }],
            ThemeCategories = [new() { Name = "Authors" }, new() { Name = "Modern", ParentName = "Authors" }]
        });
        await db.SaveChangesAsync();
    }

    private static CompleteWelcomeRequest CollectionWelcome() => new()
    {
        WorkspaceName = "  Library  ", Collection = new SetupCollectionRequest { Name = "  Books  ", ThemeId = 10 }
    };

    private async Task AssertNoWelcomeCollection()
    {
        await using var db = fixture.CreateContext();
        Assert.Empty(await db.Collections.ToListAsync());
        Assert.Empty(await db.Categories.ToListAsync());
        Assert.Empty(await db.CollectionItemTemplates.ToListAsync());
        Assert.Empty(await db.WorkspaceStatistics.ToListAsync());
        Assert.Null((await db.Workspaces.SingleAsync(w => w.Id == 1)).WelcomeCollectionId);
    }

    private sealed class FailSecondSave(Exception failure) : SaveChangesInterceptor
    {
        private int _count;
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (++_count == 2) throw failure;
            return ValueTask.FromResult(result);
        }
    }
}
