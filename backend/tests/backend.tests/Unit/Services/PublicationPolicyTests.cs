using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using OneBigHead.Server.Services.Publishing;

namespace backend.tests.Unit.Services;

[Trait("Category", "Unit")]
public class PublicationPolicyTests
{
    private static PublicationSnapshot Snapshot(params PublicationKey[] selection) => new(
        new Workspace { Id = 1, Name = "Library", Slug = "library" }, selection.ToHashSet(),
        new() { [1] = new() { Id = 1, WorkspaceId = 1, Name = "Books" }, [2] = new() { Id = 2, WorkspaceId = 1, Name = "Records", Visibility = Visibility.Public } },
        new() {
            [1] = Category(1, null, Visibility.Private), [2] = Category(2, 1, Visibility.Private),
            [3] = Category(3, 2, Visibility.Public), [4] = Category(4, null, Visibility.Public),
            [5] = Category(5, 4, Visibility.Private), [10] = Category(10, null, Visibility.Public, 2)
        },
        new() { [1] = Item(1, 3, Visibility.Private), [2] = Item(2, 3, Visibility.Public), [3] = Item(3, 4, Visibility.Public),
            [4] = Item(4, null, Visibility.Public), [5] = Item(5, 5, Visibility.Public), [10] = Item(10, 10, Visibility.Public, 2) });
    private static Category Category(int id, int? parent, Visibility visibility, int collectionId = 1) => new()
    { Id = id, WorkspaceId = 1, CollectionId = collectionId, ParentCategoryId = parent, Visibility = visibility, Name = $"Category {id}" };
    private static Item Item(int id, int? category, Visibility visibility, int collectionId = 1) => new()
    { Id = id, WorkspaceId = 1, CollectionId = collectionId, CategoryId = category, Visibility = visibility, Name = $"Item {id}" };
    private static PublicationResult<PublicationPlan> Plan(PublicationSnapshot snapshot, PublishAction action = PublishAction.Publish) =>
        PublicationPlan.Build(snapshot, action, new VisibilityService());

    [Fact]
    public void Publish_PlansOnlyChangedFields_AndDeduplicatesAncestorConsent()
    {
        var snapshot = Snapshot(new PublicationKey("item", 1), new("item", 2));
        var plan = Plan(snapshot).Value!;
        Assert.Single(plan.Changed);
        Assert.Equal(1, plan.Changed[0].Id);
        Assert.Equal(["collection", "category", "category"], plan.Promoted.Select(entity => entity.Type));
        Assert.Equal([1, 1, 2], plan.Promoted.Select(entity => entity.Id));
        Assert.Equal(3, plan.Requirements.Count);
        Assert.Equal(Visibility.Private, snapshot.Collections[1].Visibility);
        Assert.Equal(Visibility.Private, snapshot.Items[1].Visibility);
        Assert.Equal(Visibility.Private, snapshot.Categories[2].Visibility);
    }

    [Fact]
    public void Publish_SelectedAncestorsNeedNoAdditionalConsent_AndUncategorizedItemsWork()
    {
        var snapshot = Snapshot(new PublicationKey("collection", 1), new("category", 1), new("category", 2), new("item", 1), new("item", 4));
        var plan = Plan(snapshot).Value!;
        Assert.Empty(plan.Requirements);
        Assert.Empty(plan.Promoted);
        Assert.Equal(4, plan.Changed.Count);
        foreach (var entity in plan.Changed) snapshot.Apply(entity, Visibility.Public);
        Assert.True(Plan(snapshot).Value!.Changed.Count == 0);
        Assert.Throws<ArgumentException>(() => snapshot.Apply(new() { Type = "unknown", Id = 1, Name = "Invalid" }, Visibility.Public));
    }

    [Fact]
    public void Publish_RequiresGalleryUrlOnlyWhenMissing()
    {
        var snapshot = Snapshot(new PublicationKey("collection", 2));
        snapshot.Workspace.Slug = " ";
        var requirement = Assert.IsType<WorkspaceSlugRequiredRequirement>(Assert.Single(Plan(snapshot).Value!.Requirements));
        Assert.Equal(1, requirement.WorkspaceId);
        Assert.Equal("Library", requirement.WorkspaceName);
    }

    [Theory]
    [InlineData("self")]
    [InlineData("cycle")]
    [InlineData("missing")]
    [InlineData("foreign-collection")]
    public void Publish_RejectsInvalidAncestry_WithoutChangingVisibility(string problem)
    {
        var snapshot = Snapshot(new PublicationKey("item", 1));
        snapshot.Categories[1].ParentCategoryId = problem switch { "self" => 1, "cycle" => 3, "missing" => 999, _ => 10 };
        var result = Plan(snapshot);
        Assert.Equal(PublicationFailure.Conflict, result.Error!.Kind);
        Assert.Null(result.Value);
        Assert.Equal(Visibility.Private, snapshot.Collections[1].Visibility);
    }

    [Fact]
    public void Publish_HandlesDeepAncestryWithoutRecursion()
    {
        var snapshot = Snapshot(new PublicationKey("category", 20000));
        snapshot.Categories.Clear();
        for (var id = 1; id <= 20000; id++) snapshot.Categories[id] = Category(id, id == 1 ? null : id - 1, Visibility.Private);
        var result = Plan(snapshot);
        Assert.Null(result.Error);
        Assert.Equal(20000, result.Value!.Promoted.Count);
        Assert.Equal(20000, Assert.Single(result.Value.Changed).Id);
    }

    [Fact]
    public void Unpublish_CategoryCountsOnlyVisibleDescendantsAndTheirItems()
    {
        var snapshot = Snapshot(new PublicationKey("category", 2));
        snapshot.Collections[1].Visibility = Visibility.Public;
        snapshot.Categories[1].Visibility = snapshot.Categories[2].Visibility = Visibility.Public;
        var plan = Plan(snapshot, PublishAction.Unpublish).Value!;
        var impact = Assert.IsType<UnpublishWillHideChildrenRequirement>(Assert.Single(plan.Requirements));
        Assert.Equal("category", impact.EntityType);
        Assert.Equal(2, impact.EntityId);
        Assert.Equal(1, impact.AffectedPublicItems);
        Assert.Equal(1, impact.AffectedPublicCategories);
        Assert.Empty(plan.Promoted);
        Assert.Equal(2, Assert.Single(plan.Changed).Id);
    }

    [Fact]
    public void Unpublish_CollectionCountsVisibleChildrenIncludingUncategorizedItems()
    {
        var snapshot = Snapshot(new PublicationKey("collection", 1), new("item", 2));
        snapshot.Collections[1].Visibility = Visibility.Public;
        snapshot.Categories[1].Visibility = snapshot.Categories[2].Visibility = Visibility.Public;
        var plan = Plan(snapshot, PublishAction.Unpublish).Value!;
        var impact = Assert.IsType<UnpublishWillHideChildrenRequirement>(Assert.Single(plan.Requirements));
        Assert.Equal("Books", impact.EntityName);
        Assert.Equal(3, impact.AffectedPublicItems);
        Assert.Equal(4, impact.AffectedPublicCategories);
        Assert.Equal(2, plan.Changed.Count);
    }

    [Fact]
    public void Unpublish_AlreadyHiddenEntriesNeedNoConsent_AndCyclesRemainSafe()
    {
        var snapshot = Snapshot(new PublicationKey("category", 1), new("collection", 1), new("item", 1));
        snapshot.Categories[1].ParentCategoryId = 3;
        var plan = Plan(snapshot, PublishAction.Unpublish).Value!;
        Assert.Empty(plan.Requirements);
        Assert.Empty(plan.Changed);
        Assert.Empty(plan.Promoted);
    }

    [Theory]
    [InlineData(null, false)] [InlineData("", false)] [InlineData("ab", false)] [InlineData("abc", true)]
    [InlineData("a-b", true)] [InlineData("a-2", true)] [InlineData("-abc", false)] [InlineData("abc-", false)]
    [InlineData("a--b", false)] [InlineData("ABC", false)] [InlineData("a/b", false)] [InlineData("abc def", false)]
    public void Consent_ValidatesGalleryUrl(string? slug, bool valid) => Assert.Equal(valid, PublicationConsent.IsValidSlug(slug));

    [Fact]
    public void Consent_ValidatesLimitsAndRequiresExactlyOneUrl()
    {
        Assert.True(PublicationConsent.IsValidSlug(new string('a', 50)));
        Assert.False(PublicationConsent.IsValidSlug(new string('a', 51)));
        var requirement = new WorkspaceSlugRequiredRequirement { WorkspaceName = "Library" };
        Assert.False(PublicationConsent.IsResolved(requirement, []));
        Assert.False(PublicationConsent.IsResolved(requirement, [new WorkspaceSlugResolution { Slug = "ab" }]));
        Assert.False(PublicationConsent.IsResolved(requirement, [new WorkspaceSlugResolution { Slug = "abc" }, new WorkspaceSlugResolution { Slug = "def" }]));
        Assert.True(PublicationConsent.IsResolved(requirement, [new WorkspaceSlugResolution { Slug = "abc" }]));
    }

    [Fact]
    public void Consent_MatchesEntityTypeIdentityAndReviewedImpact_AndRejectsUnknownRequirements()
    {
        var collection = new CollectionNotPublicRequirement { CollectionId = 2, CollectionName = "Books" };
        var category = new CategoryNotPublicRequirement { CategoryId = 2, CategoryName = "Classics" };
        var impact = new UnpublishWillHideChildrenRequirement { EntityId = 2, EntityType = "category", EntityName = "Classics", AffectedPublicItems = 3, AffectedPublicCategories = 1 };
        Assert.False(PublicationConsent.IsResolved(collection, [new CollectionNotPublicResolution { CollectionId = 1 }]));
        Assert.False(PublicationConsent.IsResolved(category, [new CategoryNotPublicResolution { CategoryId = 1 }]));
        Assert.True(PublicationConsent.IsResolved(collection, [new CollectionNotPublicResolution { CollectionId = 2 }]));
        Assert.True(PublicationConsent.IsResolved(category, [new CategoryNotPublicResolution { CategoryId = 2 }]));
        var resolution = new UnpublishWillHideChildrenResolution { EntityId = 2, EntityType = "collection", AffectedPublicItems = 3, AffectedPublicCategories = 1 };
        Assert.False(PublicationConsent.IsResolved(impact, [resolution]));
        resolution.EntityType = "category"; resolution.EntityId = 1;
        Assert.False(PublicationConsent.IsResolved(impact, [resolution]));
        resolution.EntityId = 2; resolution.AffectedPublicItems = 2;
        Assert.False(PublicationConsent.IsResolved(impact, [resolution]));
        resolution.AffectedPublicItems = 3; resolution.AffectedPublicCategories = 2;
        Assert.False(PublicationConsent.IsResolved(impact, [resolution]));
        resolution.AffectedPublicCategories = 1;
        Assert.True(PublicationConsent.IsResolved(impact, [resolution]));
        Assert.False(PublicationConsent.IsResolved(new UnknownRequirement(), []));
    }
    private sealed class UnknownRequirement : PublishRequirement;
}
