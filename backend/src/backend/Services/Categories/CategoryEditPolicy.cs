using OneBigHead.Server.Models;
using OneBigHead.Server.Utilities;

namespace OneBigHead.Server.Services.Categories;

public static class CategoryEditPolicy
{
    public static string? ValidateFields(string name, string? description)
    {
        if (string.IsNullOrWhiteSpace(name)) return "A category name is required.";
        if (name.Trim().Length > 200) return "Category names cannot exceed 200 characters.";
        if (string.Equals(name.Trim(), Constants.CategoryNames.UnassignedItems, StringComparison.OrdinalIgnoreCase))
            return "The name 'Unassigned Items' is reserved for system use.";
        if (description?.Length > 1000) return "Category descriptions cannot exceed 1000 characters.";
        return null;
    }

    /// <summary>The lookup contains only categories in the target workspace and collection.</summary>
    public static bool IsValidParent(int? categoryId, int? parentId, IReadOnlyDictionary<int, Category> categories)
    {
        var visited = new HashSet<int>();
        while (parentId is int id)
        {
            if (id == categoryId || !visited.Add(id) || !categories.TryGetValue(id, out var parent) || parent.IsSystem)
                return false;
            parentId = parent.ParentCategoryId;
        }
        return true;
    }
}
