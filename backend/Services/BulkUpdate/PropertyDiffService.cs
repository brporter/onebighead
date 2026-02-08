using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.BulkUpdate;

public class PropertyDiffService : IPropertyDiffService
{
    public PropertyDiff ComputeDiff(
        List<PropertyIdentifier> oldProps,
        List<PropertyIdentifier> newProps,
        List<PropertyRenameMapping>? renameMappings = null)
    {
        var changes = new List<PropertyChange>();

        // Build lookup dictionaries: (Category, Name) → index
        var oldLookup = new Dictionary<(string, string), int>();
        for (var i = 0; i < oldProps.Count; i++)
        {
            oldLookup[(oldProps[i].Category, oldProps[i].Name)] = i;
        }

        var newLookup = new Dictionary<(string, string), int>();
        for (var i = 0; i < newProps.Count; i++)
        {
            newLookup[(newProps[i].Category, newProps[i].Name)] = i;
        }

        // Track which old/new props are accounted for by renames
        var renamedOld = new HashSet<(string, string)>();
        var renamedNew = new HashSet<(string, string)>();

        // Process explicit rename mappings first
        if (renameMappings != null)
        {
            foreach (var mapping in renameMappings)
            {
                var oldKey = (mapping.OldCategory, mapping.OldName);
                var newKey = (mapping.NewCategory, mapping.NewName);

                if (oldLookup.ContainsKey(oldKey) && newLookup.ContainsKey(newKey))
                {
                    changes.Add(new PropertyChange(
                        PropertyChangeType.Renamed,
                        mapping.OldCategory,
                        mapping.OldName,
                        mapping.NewCategory,
                        mapping.NewName));

                    renamedOld.Add(oldKey);
                    renamedNew.Add(newKey);
                }
            }
        }

        // Properties in old but not in new (and not renamed) → Removed
        foreach (var oldProp in oldProps)
        {
            var key = (oldProp.Category, oldProp.Name);
            if (!renamedOld.Contains(key) && !newLookup.ContainsKey(key))
            {
                changes.Add(new PropertyChange(PropertyChangeType.Removed, oldProp.Category, oldProp.Name));
            }
        }

        // Properties in new but not in old (and not renamed) → Added
        foreach (var newProp in newProps)
        {
            var key = (newProp.Category, newProp.Name);
            if (!renamedNew.Contains(key) && !oldLookup.ContainsKey(key))
            {
                changes.Add(new PropertyChange(PropertyChangeType.Added, newProp.Category, newProp.Name));
            }
        }

        // Properties in both but at different indices → Reordered
        foreach (var newProp in newProps)
        {
            var key = (newProp.Category, newProp.Name);
            if (!renamedNew.Contains(key) && oldLookup.TryGetValue(key, out var oldIndex))
            {
                var newIndex = newLookup[key];
                if (oldIndex != newIndex)
                {
                    changes.Add(new PropertyChange(PropertyChangeType.Reordered, newProp.Category, newProp.Name));
                }
            }
        }

        return new PropertyDiff(changes);
    }

    public List<ItemProperty> ApplyDiff(
        List<ItemProperty> targetProperties,
        PropertyDiff diff,
        List<PropertyIdentifier> newPropertyOrder)
    {
        // 1. Copy target properties
        var result = targetProperties.Select(p => new ItemProperty(p.Category, p.Name, p.Value)).ToList();

        // 2. Apply Removed: find by (Category, Name), remove if present
        foreach (var change in diff.Changes.Where(c => c.Type == PropertyChangeType.Removed))
        {
            result.RemoveAll(p => p.Category == change.Category && p.Name == change.Name);
        }

        // 3. Apply Renamed: find by (OldCategory, OldName), update to (NewCategory, NewName)
        foreach (var change in diff.Changes.Where(c => c.Type == PropertyChangeType.Renamed))
        {
            for (var i = 0; i < result.Count; i++)
            {
                if (result[i].Category == change.Category && result[i].Name == change.Name)
                {
                    result[i] = new ItemProperty(change.NewCategory!, change.NewName!, result[i].Value);
                }
            }
        }

        // 4. Apply Added: add with Value="" if (Category, Name) doesn't already exist
        foreach (var change in diff.Changes.Where(c => c.Type == PropertyChangeType.Added))
        {
            var exists = result.Any(p => p.Category == change.Category && p.Name == change.Name);
            if (!exists)
            {
                result.Add(new ItemProperty(change.Category, change.Name, ""));
            }
        }

        // 5. Apply ordering
        var orderLookup = new Dictionary<(string, string), int>();
        for (var i = 0; i < newPropertyOrder.Count; i++)
        {
            orderLookup[(newPropertyOrder[i].Category, newPropertyOrder[i].Name)] = i;
        }

        // Partition into template props and custom props
        var templateProps = new List<(ItemProperty Prop, int Order)>();
        var customProps = new List<ItemProperty>();

        foreach (var prop in result)
        {
            if (orderLookup.TryGetValue((prop.Category, prop.Name), out var order))
            {
                templateProps.Add((prop, order));
            }
            else
            {
                customProps.Add(prop);
            }
        }

        // Sort template props by their index in newPropertyOrder
        templateProps.Sort((a, b) => a.Order.CompareTo(b.Order));

        // Result = template props in template order, then custom props in original relative order
        return templateProps.Select(tp => tp.Prop).Concat(customProps).ToList();
    }
}
