using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Publishing;

/// <summary>Computes consent and exact visibility changes without modifying persisted fields.</summary>
internal sealed record PublicationPlan(List<PublishRequirement> Requirements, List<ChangedEntityInfo> Changed, List<ChangedEntityInfo> Promoted)
{
    public static PublicationResult<PublicationPlan> Build(PublicationSnapshot snapshot, PublishAction action, IVisibilityService visibility)
    {
        var requirements = new List<PublishRequirement>();
        var changes = new Dictionary<PublicationKey, ChangedEntityInfo>();
        var desired = action == PublishAction.Publish ? Visibility.Public : Visibility.Private;
        if (action == PublishAction.Publish && string.IsNullOrWhiteSpace(snapshot.Workspace.Slug))
            requirements.Add(new WorkspaceSlugRequiredRequirement { WorkspaceId = snapshot.Workspace.Id, WorkspaceName = snapshot.Workspace.Name });

        void Add(string type, int id, string name, Visibility current)
        {
            if (current == desired) return;
            var key = new PublicationKey(type, id);
            if (!changes.TryAdd(key, new ChangedEntityInfo { Type = type, Id = id, Name = name })) return;
            if (action == PublishAction.Publish && !snapshot.Selection.Contains(key))
            {
                if (type == "collection") requirements.Add(new CollectionNotPublicRequirement { CollectionId = id, CollectionName = name });
                else requirements.Add(new CategoryNotPublicRequirement { CategoryId = id, CategoryName = name });
            }
        }

        foreach (var key in snapshot.Selection)
        {
            var collectionId = key.Type switch
            {
                "item" => snapshot.Items[key.Id].CollectionId,
                "category" => snapshot.Categories[key.Id].CollectionId,
                _ => key.Id
            };
            var collection = snapshot.Collections[collectionId];
            if (action == PublishAction.Publish)
            {
                Add("collection", collection.Id, collection.Name, collection.Visibility);
                var categoryId = key.Type == "item" ? snapshot.Items[key.Id].CategoryId : key.Type == "category" ? key.Id : (int?)null;
                var path = new Stack<Category>();
                var visited = new HashSet<int>();
                while (categoryId is int id)
                {
                    if (!visited.Add(id) || !snapshot.Categories.TryGetValue(id, out var category) || category.CollectionId != collectionId)
                        return PublicationResult<PublicationPlan>.Failure(new(PublicationFailure.Conflict,
                            "A selected entry has an invalid category ancestry. Repair its category before publishing."));
                    path.Push(category);
                    categoryId = category.ParentCategoryId;
                }
                foreach (var category in path) Add("category", category.Id, category.Name, category.Visibility);
            }
            else if (key.Type != "item")
            {
                var categories = snapshot.Categories.Values.Where(category => category.CollectionId == collectionId).ToList();
                var items = snapshot.Items.Values.Where(item => item.CollectionId == collectionId).ToList();
                visibility.ComputeEffectiveVisibility(categories, collection);
                visibility.ComputeEffectiveVisibility(items, collection, categories);
                var affectedIds = key.Type == "collection" ? categories.Select(category => category.Id).ToHashSet() : Descendants(key.Id, categories);
                var affectedCategories = categories.Count(category => category.Id != (key.Type == "category" ? key.Id : 0) && affectedIds.Contains(category.Id) && category.EffectiveIsPublic);
                var affectedItems = items.Count(item => item.EffectiveIsPublic && (key.Type == "collection" || item.CategoryId is int id && affectedIds.Contains(id)));
                if (affectedItems > 0 || affectedCategories > 0)
                    requirements.Add(new UnpublishWillHideChildrenRequirement { EntityType = key.Type, EntityId = key.Id,
                        EntityName = key.Type == "collection" ? collection.Name : snapshot.Categories[key.Id].Name,
                        AffectedPublicItems = affectedItems, AffectedPublicCategories = affectedCategories });
                if (key.Type == "collection") Add(key.Type, key.Id, collection.Name, collection.Visibility);
                else { var category = snapshot.Categories[key.Id]; Add(key.Type, key.Id, category.Name, category.Visibility); }
            }
            if (key.Type == "item") { var item = snapshot.Items[key.Id]; Add(key.Type, key.Id, item.Name, item.Visibility); }
        }
        return PublicationResult<PublicationPlan>.Success(new(requirements,
            changes.Where(change => snapshot.Selection.Contains(change.Key)).Select(change => change.Value).ToList(),
            changes.Where(change => !snapshot.Selection.Contains(change.Key)).Select(change => change.Value).ToList()));
    }

    private static HashSet<int> Descendants(int root, List<Category> categories)
    {
        var children = categories.Where(category => category.ParentCategoryId.HasValue).ToLookup(category => category.ParentCategoryId!.Value);
        var result = new HashSet<int> { root };
        var pending = new Stack<int>();
        pending.Push(root);
        while (pending.TryPop(out var parent))
            foreach (var child in children[parent]) if (result.Add(child.Id)) pending.Push(child.Id);
        return result;
    }
}
