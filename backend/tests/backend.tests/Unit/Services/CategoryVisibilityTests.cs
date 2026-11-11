using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Categories;

namespace OneBigHead.Server.Tests.Unit.Services;

[Trait("Category", "Unit")]
public class CategoryVisibilityTests
{
    private static Collection Collection(Visibility visibility = Visibility.Public) =>
        new() { Id = 1, WorkspaceId = 1, Visibility = visibility };

    private static Category Category(int id, int? parent = null, Visibility visibility = Visibility.Public) =>
        new() { Id = id, WorkspaceId = 1, CollectionId = 1, ParentCategoryId = parent, Visibility = visibility };

    [Fact]
    public void EmptyCollection_HasNoCategoriesToResolve() => CategoryVisibility.Apply([], Collection());

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PublicHierarchy_IsIndependentOfInputOrder(bool reverse)
    {
        Category[] categories = [Category(1), Category(2, 1), Category(3, 2), Category(4, 1)];

        CategoryVisibility.Apply(reverse ? categories.Reverse() : categories, Collection());

        Assert.All(categories, category => Assert.True(category.EffectiveIsPublic));
    }

    [Fact]
    public void PrivateCollection_ResetsPreviouslyComputedPublicFlags()
    {
        Category[] categories = [Category(1), Category(2, 1)];
        CategoryVisibility.Apply(categories, Collection());

        CategoryVisibility.Apply(categories, Collection(Visibility.Private));

        Assert.All(categories, category => Assert.False(category.EffectiveIsPublic));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PrivateAncestor_HidesDescendantsWithoutHidingUnrelatedCategories(bool reverse)
    {
        Category[] categories = [Category(1), Category(2, 1, Visibility.Private), Category(3, 2), Category(4, 2)];

        CategoryVisibility.Apply(reverse ? categories.Reverse() : categories, Collection());

        Assert.True(categories[0].EffectiveIsPublic);
        Assert.All(categories.Skip(1), category => Assert.False(category.EffectiveIsPublic));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Cycles_AndTheirDescendants_ArePrivate(int cycleLength)
    {
        var cycle = Enumerable.Range(1, cycleLength).Select(id => Category(id, id % cycleLength + 1)).ToList();
        cycle.Add(Category(100, 1));
        var unrelated = Category(200);

        CategoryVisibility.Apply(cycle.Prepend(unrelated), Collection());

        Assert.All(cycle, category => Assert.False(category.EffectiveIsPublic));
        Assert.True(unrelated.EffectiveIsPublic);
    }

    [Theory]
    [InlineData(1, 2)]
    [InlineData(2, 1)]
    public void ForeignParents_CannotProvideVisibility(int workspaceId, int collectionId)
    {
        var parent = Category(1);
        parent.WorkspaceId = workspaceId;
        parent.CollectionId = collectionId;
        var child = Category(2, 1);

        CategoryVisibility.Apply([child, parent], Collection());

        Assert.False(parent.EffectiveIsPublic);
        Assert.False(child.EffectiveIsPublic);
    }

    [Fact]
    public void MissingParent_AndDescendants_ArePrivate()
    {
        Category[] categories = [Category(2, 999), Category(3, 2)];

        CategoryVisibility.Apply(categories, Collection());

        Assert.All(categories, category => Assert.False(category.EffectiveIsPublic));
    }

    [Fact]
    public void DeepHierarchy_ResolvesWithoutRecursion()
    {
        var categories = Enumerable.Range(1, 20_000).Select(id => Category(id, id == 1 ? null : id - 1)).ToList();

        CategoryVisibility.Apply(categories.AsEnumerable().Reverse(), Collection());

        Assert.All(categories, category => Assert.True(category.EffectiveIsPublic));
    }
}
