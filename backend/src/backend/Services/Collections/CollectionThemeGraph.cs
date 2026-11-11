using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Categories;
using OneBigHead.Server.Utilities;

namespace OneBigHead.Server.Services.Collections;

/// <summary>Builds a complete new graph before any database or caller-owned state is changed.</summary>
public static class CollectionThemeGraph
{
    public static IReadOnlyList<Category> Build(int workspaceId, CollectionTheme? theme)
    {
        var system = new Category
        {
            WorkspaceId = workspaceId,
            Name = Constants.CategoryNames.UnassignedItems,
            Description = Constants.CategoryNames.UnassignedItemsDescription,
            IsSystem = true
        };
        if (theme is null) return [system];

        var sources = theme.ThemeCategories.OrderBy(category => category.SortOrder)
            .ThenBy(category => category.Name, StringComparer.Ordinal).ToList();
        var categories = new Dictionary<string, Category>(StringComparer.Ordinal);
        foreach (var source in sources)
        {
            var error = CategoryEditPolicy.ValidateFields(source.Name, source.Description);
            if (error != null) throw new InvalidCollectionThemeException($"The selected theme contains an invalid category. {error}");
            if (source.SortOrder < 0) throw new InvalidCollectionThemeException("The selected theme contains a negative category order.");
            var name = source.Name.Trim();
            if (!categories.TryAdd(name, new Category
                {
                    WorkspaceId = workspaceId, Name = name,
                    Description = source.Description, SortOrder = source.SortOrder
                }))
                throw new InvalidCollectionThemeException("The selected theme contains duplicate category names.");
        }

        var roots = new Queue<Category>();
        foreach (var source in sources)
        {
            var category = categories[source.Name.Trim()];
            var parentName = source.ParentName?.Trim();
            if (string.IsNullOrEmpty(parentName)) roots.Enqueue(category);
            else
            {
                if (!categories.TryGetValue(parentName, out var parent))
                    throw new InvalidCollectionThemeException("The selected theme references a missing parent category.");
                category.ParentCategory = parent;
                parent.ChildCategories.Add(category);
            }
        }

        // A topological walk detects cycles without recursion or repeated ancestry scans.
        var result = new List<Category> { system };
        while (roots.TryDequeue(out var category))
        {
            result.Add(category);
            foreach (var child in category.ChildCategories) roots.Enqueue(child);
        }
        if (result.Count != categories.Count + 1)
            throw new InvalidCollectionThemeException("The selected theme contains circular category relationships.");
        return result;
    }
}
