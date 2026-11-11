using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Categories;

/// <summary>Effective visibility requires a complete, public ancestry in the same collection.</summary>
public static class CategoryVisibility
{
    public static void Apply(IEnumerable<Category> categories, Collection collection)
    {
        var lookup = categories.ToDictionary(category => category.Id);
        var resolved = new Dictionary<int, bool>();
        foreach (var category in lookup.Values)
        {
            var path = new List<Category>();
            var visited = new HashSet<int>();
            var current = category;
            var isPublic = collection.EffectiveIsPublic;

            // Resolve iteratively so a deep tree cannot exhaust the stack. Cache completed paths.
            while (isPublic)
            {
                if (resolved.TryGetValue(current.Id, out var known))
                {
                    isPublic = known;
                    break;
                }

                path.Add(current);
                if (!visited.Add(current.Id) || current.WorkspaceId != collection.WorkspaceId ||
                    current.CollectionId != collection.Id || current.Visibility != Visibility.Public)
                {
                    isPublic = false;
                    break;
                }

                if (current.ParentCategoryId is not int parentId)
                {
                    break;
                }

                if (!lookup.TryGetValue(parentId, out current))
                {
                    isPublic = false;
                    break;
                }
            }

            category.EffectiveIsPublic = isPublic;
            foreach (var ancestor in path)
            {
                ancestor.EffectiveIsPublic = isPublic;
                resolved[ancestor.Id] = isPublic;
            }
        }
    }
}
