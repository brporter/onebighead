using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Collections;
using OneBigHead.Server.Utilities;

namespace OneBigHead.Server.Tests.Unit.Services;

[Trait("Category", "Unit")]
public class CollectionThemeGraphTests
{
    [Fact]
    public void Build_PreservesOrderDescriptionAndScope_WithoutMutatingTheme()
    {
        var source = new CollectionTheme
        {
            ThemeCategories = [
                new() { Name = " Child ", ParentName = " Root ", Description = "Child description", SortOrder = 3 },
                new() { Name = " Second ", ParentName = "  ", SortOrder = 8 },
                new() { Name = " Root ", SortOrder = 5 },
                new() { Name = "Grandchild", ParentName = "Child", SortOrder = 0 },
                new() { Name = "Alpha", ParentName = "Root", SortOrder = 3 }]
        };
        var rows = CollectionThemeGraph.Build(7, source);
        var system = Assert.Single(rows, category => category.IsSystem);
        Assert.Equal(Constants.CategoryNames.UnassignedItems, system.Name);
        Assert.Equal(Constants.CategoryNames.UnassignedItemsDescription, system.Description);
        var root = rows.Single(category => category.Name == "Root");
        var child = rows.Single(category => category.Name == "Child");
        var grandchild = rows.Single(category => category.Name == "Grandchild");
        Assert.Same(root, child.ParentCategory);
        Assert.Same(child, grandchild.ParentCategory);
        Assert.Contains(child, root.ChildCategories);
        Assert.Null(rows.Single(category => category.Name == "Second").ParentCategory);
        Assert.Equal("Child description", child.Description);
        Assert.Equal(3, child.SortOrder);
        Assert.Equal(5, root.SortOrder);
        Assert.All(rows, category => { Assert.Equal(7, category.WorkspaceId); Assert.Equal(Visibility.Private, category.Visibility); });
        Assert.Equal(" Child ", source.ThemeCategories.First().Name);
        Assert.All(source.ThemeCategories, category => Assert.Equal(0, category.Id));
        var rebuilt = CollectionThemeGraph.Build(8, source);
        Assert.NotSame(child, rebuilt.Single(category => category.Name == "Child"));
        Assert.All(rebuilt, category => Assert.Equal(8, category.WorkspaceId));
    }

    [Fact]
    public void Build_HandlesEmptyThemesAndTwentyThousandLevelsWithoutRecursion()
    {
        Assert.True(Assert.Single(CollectionThemeGraph.Build(1, null)).IsSystem);
        Assert.True(Assert.Single(CollectionThemeGraph.Build(1, new CollectionTheme())).IsSystem);
        var source = new CollectionTheme
        {
            ThemeCategories = Enumerable.Range(0, 20_000).Reverse().Select(index => new CollectionThemeCategory
            { Name = $"Level {index}", ParentName = index == 0 ? null : $"Level {index - 1}" }).ToList()
        };
        var rows = CollectionThemeGraph.Build(1, source);
        Assert.Equal(20_001, rows.Count);
        Assert.Equal("Level 19999", rows[^1].Name);
        Assert.Same(rows[^2], rows[^1].ParentCategory);
    }

    [Theory]
    [InlineData("duplicate", "duplicate")]
    [InlineData("missing", "missing")]
    [InlineData("case", "missing")]
    [InlineData("self", "circular")]
    [InlineData("cycle", "circular")]
    [InlineData("name", "name is required")]
    [InlineData("reserved", "reserved")]
    [InlineData("order", "negative")]
    public void Build_RejectsAnInvalidThemeAsAWhole(string scenario, string message)
    {
        var sources = new List<CollectionThemeCategory> { new() { Name = "Root" } };
        switch (scenario)
        {
            case "duplicate": sources.Add(new() { Name = " Root " }); break;
            case "missing": sources.Add(new() { Name = "Child", ParentName = "Missing" }); break;
            case "case": sources.Add(new() { Name = "Child", ParentName = "root" }); break;
            case "self": sources.Add(new() { Name = "Child", ParentName = "Child" }); break;
            case "cycle": sources.AddRange([new() { Name = "A", ParentName = "B" }, new() { Name = "B", ParentName = "A" }, new() { Name = "Descendant", ParentName = "B" }]); break;
            case "name": sources.Add(new() { Name = " " }); break;
            case "reserved": sources.Add(new() { Name = " unassigned items " }); break;
            case "order": sources.Add(new() { Name = "Child", SortOrder = -1 }); break;
        }
        var exception = Assert.Throws<InvalidCollectionThemeException>(() => CollectionThemeGraph.Build(1, new CollectionTheme { ThemeCategories = sources }));
        Assert.Contains(message, exception.Message, StringComparison.OrdinalIgnoreCase);
    }
}
