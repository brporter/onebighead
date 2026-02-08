using OneBigHead.Server.Models;
using OneBigHead.Server.Services.BulkUpdate;

namespace OneBigHead.Server.Tests.Services;

[Trait("Category", "Unit")]
public class PropertyDiffServiceTests
{
    private readonly PropertyDiffService _service = new();

    #region ComputeDiff Tests

    [Fact]
    public void ComputeDiff_EmptyToEmpty_ReturnsNoChanges()
    {
        var diff = _service.ComputeDiff(new List<PropertyIdentifier>(), new List<PropertyIdentifier>());
        Assert.Empty(diff.Changes);
    }

    [Fact]
    public void ComputeDiff_AddOnly_ReturnsAddedChanges()
    {
        var oldProps = new List<PropertyIdentifier>();
        var newProps = new List<PropertyIdentifier>
        {
            new("Specs", "CPU"),
            new("Specs", "RAM"),
        };

        var diff = _service.ComputeDiff(oldProps, newProps);

        Assert.Equal(2, diff.Changes.Count);
        Assert.All(diff.Changes, c => Assert.Equal(PropertyChangeType.Added, c.Type));
        Assert.Contains(diff.Changes, c => c.Category == "Specs" && c.Name == "CPU");
        Assert.Contains(diff.Changes, c => c.Category == "Specs" && c.Name == "RAM");
    }

    [Fact]
    public void ComputeDiff_RemoveOnly_ReturnsRemovedChanges()
    {
        var oldProps = new List<PropertyIdentifier>
        {
            new("Specs", "CPU"),
            new("Specs", "RAM"),
        };
        var newProps = new List<PropertyIdentifier>();

        var diff = _service.ComputeDiff(oldProps, newProps);

        Assert.Equal(2, diff.Changes.Count);
        Assert.All(diff.Changes, c => Assert.Equal(PropertyChangeType.Removed, c.Type));
    }

    [Fact]
    public void ComputeDiff_RenameOnly_ReturnsRenamedChanges()
    {
        var oldProps = new List<PropertyIdentifier> { new("Specs", "CPU") };
        var newProps = new List<PropertyIdentifier> { new("Hardware", "Processor") };
        var mappings = new List<PropertyRenameMapping>
        {
            new("Specs", "CPU", "Hardware", "Processor"),
        };

        var diff = _service.ComputeDiff(oldProps, newProps, mappings);

        var change = Assert.Single(diff.Changes);
        Assert.Equal(PropertyChangeType.Renamed, change.Type);
        Assert.Equal("Specs", change.Category);
        Assert.Equal("CPU", change.Name);
        Assert.Equal("Hardware", change.NewCategory);
        Assert.Equal("Processor", change.NewName);
    }

    [Fact]
    public void ComputeDiff_ReorderOnly_ReturnsReorderedChanges()
    {
        var oldProps = new List<PropertyIdentifier>
        {
            new("Specs", "CPU"),
            new("Specs", "RAM"),
        };
        var newProps = new List<PropertyIdentifier>
        {
            new("Specs", "RAM"),
            new("Specs", "CPU"),
        };

        var diff = _service.ComputeDiff(oldProps, newProps);

        Assert.Equal(2, diff.Changes.Count);
        Assert.All(diff.Changes, c => Assert.Equal(PropertyChangeType.Reordered, c.Type));
    }

    [Fact]
    public void ComputeDiff_Combined_ReturnsAllChangeTypes()
    {
        var oldProps = new List<PropertyIdentifier>
        {
            new("Specs", "CPU"),
            new("Specs", "RAM"),
            new("Details", "Color"),
        };
        var newProps = new List<PropertyIdentifier>
        {
            new("Hardware", "Processor"),
            new("Details", "Color"),
            new("Details", "Weight"),
        };
        var mappings = new List<PropertyRenameMapping>
        {
            new("Specs", "CPU", "Hardware", "Processor"),
        };

        var diff = _service.ComputeDiff(oldProps, newProps, mappings);

        Assert.Contains(diff.Changes, c => c.Type == PropertyChangeType.Renamed && c.Category == "Specs" && c.Name == "CPU");
        Assert.Contains(diff.Changes, c => c.Type == PropertyChangeType.Removed && c.Category == "Specs" && c.Name == "RAM");
        Assert.Contains(diff.Changes, c => c.Type == PropertyChangeType.Added && c.Category == "Details" && c.Name == "Weight");
    }

    [Fact]
    public void ComputeDiff_SameProperties_ReturnsNoChanges()
    {
        var props = new List<PropertyIdentifier>
        {
            new("Specs", "CPU"),
            new("Specs", "RAM"),
        };

        var diff = _service.ComputeDiff(props, props);

        Assert.Empty(diff.Changes);
    }

    [Fact]
    public void ComputeDiff_RenameMapping_DoesNotProduceAddOrRemove()
    {
        var oldProps = new List<PropertyIdentifier> { new("A", "X") };
        var newProps = new List<PropertyIdentifier> { new("B", "Y") };
        var mappings = new List<PropertyRenameMapping> { new("A", "X", "B", "Y") };

        var diff = _service.ComputeDiff(oldProps, newProps, mappings);

        Assert.DoesNotContain(diff.Changes, c => c.Type == PropertyChangeType.Added);
        Assert.DoesNotContain(diff.Changes, c => c.Type == PropertyChangeType.Removed);
        Assert.Single(diff.Changes);
        Assert.Equal(PropertyChangeType.Renamed, diff.Changes[0].Type);
    }

    #endregion

    #region ApplyDiff Tests

    [Fact]
    public void ApplyDiff_AddToEmpty_AddsProperties()
    {
        var target = new List<ItemProperty>();
        var diff = new PropertyDiff(new List<PropertyChange>
        {
            new(PropertyChangeType.Added, "Specs", "CPU"),
            new(PropertyChangeType.Added, "Specs", "RAM"),
        });
        var order = new List<PropertyIdentifier>
        {
            new("Specs", "CPU"),
            new("Specs", "RAM"),
        };

        var result = _service.ApplyDiff(target, diff, order);

        Assert.Equal(2, result.Count);
        Assert.Equal("CPU", result[0].Name);
        Assert.Equal("RAM", result[1].Name);
        Assert.All(result, p => Assert.Equal("", p.Value));
    }

    [Fact]
    public void ApplyDiff_AddWhenExists_SkipsExisting()
    {
        var target = new List<ItemProperty>
        {
            new("Specs", "CPU", "Intel i7"),
        };
        var diff = new PropertyDiff(new List<PropertyChange>
        {
            new(PropertyChangeType.Added, "Specs", "CPU"),
            new(PropertyChangeType.Added, "Specs", "RAM"),
        });
        var order = new List<PropertyIdentifier>
        {
            new("Specs", "CPU"),
            new("Specs", "RAM"),
        };

        var result = _service.ApplyDiff(target, diff, order);

        Assert.Equal(2, result.Count);
        Assert.Equal("Intel i7", result[0].Value); // Value preserved
        Assert.Equal("", result[1].Value); // New property has empty value
    }

    [Fact]
    public void ApplyDiff_RemoveExisting_RemovesProperty()
    {
        var target = new List<ItemProperty>
        {
            new("Specs", "CPU", "Intel i7"),
            new("Specs", "RAM", "16GB"),
        };
        var diff = new PropertyDiff(new List<PropertyChange>
        {
            new(PropertyChangeType.Removed, "Specs", "RAM"),
        });
        var order = new List<PropertyIdentifier> { new("Specs", "CPU") };

        var result = _service.ApplyDiff(target, diff, order);

        Assert.Single(result);
        Assert.Equal("CPU", result[0].Name);
    }

    [Fact]
    public void ApplyDiff_RemoveMissing_SkipsGracefully()
    {
        var target = new List<ItemProperty>
        {
            new("Specs", "CPU", "Intel i7"),
        };
        var diff = new PropertyDiff(new List<PropertyChange>
        {
            new(PropertyChangeType.Removed, "Specs", "RAM"),
        });
        var order = new List<PropertyIdentifier> { new("Specs", "CPU") };

        var result = _service.ApplyDiff(target, diff, order);

        Assert.Single(result);
        Assert.Equal("CPU", result[0].Name);
    }

    [Fact]
    public void ApplyDiff_RenameExisting_UpdatesCategoryAndName()
    {
        var target = new List<ItemProperty>
        {
            new("Specs", "CPU", "Intel i7"),
        };
        var diff = new PropertyDiff(new List<PropertyChange>
        {
            new(PropertyChangeType.Renamed, "Specs", "CPU", "Hardware", "Processor"),
        });
        var order = new List<PropertyIdentifier> { new("Hardware", "Processor") };

        var result = _service.ApplyDiff(target, diff, order);

        Assert.Single(result);
        Assert.Equal("Hardware", result[0].Category);
        Assert.Equal("Processor", result[0].Name);
        Assert.Equal("Intel i7", result[0].Value); // Value preserved
    }

    [Fact]
    public void ApplyDiff_RenameMissing_SkipsGracefully()
    {
        var target = new List<ItemProperty>
        {
            new("Specs", "RAM", "16GB"),
        };
        var diff = new PropertyDiff(new List<PropertyChange>
        {
            new(PropertyChangeType.Renamed, "Specs", "CPU", "Hardware", "Processor"),
        });
        var order = new List<PropertyIdentifier>
        {
            new("Hardware", "Processor"),
            new("Specs", "RAM"),
        };

        var result = _service.ApplyDiff(target, diff, order);

        Assert.Single(result);
        Assert.Equal("Specs", result[0].Category);
        Assert.Equal("RAM", result[0].Name);
    }

    [Fact]
    public void ApplyDiff_ReorderWithCustomProps_PreservesCustomPropsAtEnd()
    {
        var target = new List<ItemProperty>
        {
            new("Specs", "CPU", "Intel i7"),
            new("Custom", "Serial", "ABC123"),
            new("Specs", "RAM", "16GB"),
        };
        var diff = new PropertyDiff(new List<PropertyChange>
        {
            new(PropertyChangeType.Reordered, "Specs", "RAM"),
            new(PropertyChangeType.Reordered, "Specs", "CPU"),
        });
        var order = new List<PropertyIdentifier>
        {
            new("Specs", "RAM"),
            new("Specs", "CPU"),
        };

        var result = _service.ApplyDiff(target, diff, order);

        Assert.Equal(3, result.Count);
        Assert.Equal("RAM", result[0].Name);    // Template prop first (reordered)
        Assert.Equal("CPU", result[1].Name);     // Template prop second
        Assert.Equal("Serial", result[2].Name);  // Custom prop at end
    }

    [Fact]
    public void ApplyDiff_CombinedOps_AppliesAllCorrectly()
    {
        var target = new List<ItemProperty>
        {
            new("Specs", "CPU", "Intel i7"),
            new("Specs", "RAM", "16GB"),
            new("Details", "Color", "Black"),
            new("Custom", "Notes", "My notes"),
        };
        var diff = new PropertyDiff(new List<PropertyChange>
        {
            new(PropertyChangeType.Removed, "Specs", "RAM"),
            new(PropertyChangeType.Renamed, "Specs", "CPU", "Hardware", "Processor"),
            new(PropertyChangeType.Added, "Details", "Weight"),
        });
        var order = new List<PropertyIdentifier>
        {
            new("Hardware", "Processor"),
            new("Details", "Color"),
            new("Details", "Weight"),
        };

        var result = _service.ApplyDiff(target, diff, order);

        Assert.Equal(4, result.Count);
        Assert.Equal("Processor", result[0].Name);
        Assert.Equal("Intel i7", result[0].Value);
        Assert.Equal("Color", result[1].Name);
        Assert.Equal("Black", result[1].Value);
        Assert.Equal("Weight", result[2].Name);
        Assert.Equal("", result[2].Value);
        Assert.Equal("Notes", result[3].Name);
        Assert.Equal("My notes", result[3].Value);
    }

    [Fact]
    public void ApplyDiff_EmptyDiff_ReturnsOriginalOrder()
    {
        var target = new List<ItemProperty>
        {
            new("Specs", "CPU", "Intel i7"),
            new("Specs", "RAM", "16GB"),
        };
        var diff = new PropertyDiff(new List<PropertyChange>());
        var order = new List<PropertyIdentifier>
        {
            new("Specs", "CPU"),
            new("Specs", "RAM"),
        };

        var result = _service.ApplyDiff(target, diff, order);

        Assert.Equal(2, result.Count);
        Assert.Equal("CPU", result[0].Name);
        Assert.Equal("RAM", result[1].Name);
    }

    [Fact]
    public void ApplyDiff_EmptyTarget_WithAdds_CreatesNewProperties()
    {
        var target = new List<ItemProperty>();
        var diff = new PropertyDiff(new List<PropertyChange>
        {
            new(PropertyChangeType.Added, "Specs", "CPU"),
        });
        var order = new List<PropertyIdentifier> { new("Specs", "CPU") };

        var result = _service.ApplyDiff(target, diff, order);

        Assert.Single(result);
        Assert.Equal("CPU", result[0].Name);
        Assert.Equal("", result[0].Value);
    }

    [Fact]
    public void ApplyDiff_DoesNotMutateOriginal()
    {
        var target = new List<ItemProperty>
        {
            new("Specs", "CPU", "Intel i7"),
        };
        var diff = new PropertyDiff(new List<PropertyChange>
        {
            new(PropertyChangeType.Renamed, "Specs", "CPU", "Hardware", "Processor"),
        });
        var order = new List<PropertyIdentifier> { new("Hardware", "Processor") };

        _service.ApplyDiff(target, diff, order);

        // Original should be unchanged
        Assert.Equal("Specs", target[0].Category);
        Assert.Equal("CPU", target[0].Name);
    }

    [Fact]
    public void ComputeDiff_And_ApplyDiff_RenameAndReorderSameProperty()
    {
        // Scenario: user moves "CPU" from position 3 to position 1 AND renames it to "Foobar"
        var oldProps = new List<PropertyIdentifier>
        {
            new("Specs", "RAM"),
            new("Details", "Color"),
            new("Specs", "CPU"),
        };
        var newProps = new List<PropertyIdentifier>
        {
            new("Specs", "Foobar"),
            new("Specs", "RAM"),
            new("Details", "Color"),
        };
        var renameMappings = new List<PropertyRenameMapping>
        {
            new("Specs", "CPU", "Specs", "Foobar"),
        };

        // ComputeDiff should produce a Renamed change but NOT a redundant Reordered for Foobar
        var diff = _service.ComputeDiff(oldProps, newProps, renameMappings);

        Assert.Contains(diff.Changes, c =>
            c.Type == PropertyChangeType.Renamed &&
            c.Category == "Specs" && c.Name == "CPU" &&
            c.NewCategory == "Specs" && c.NewName == "Foobar");
        Assert.DoesNotContain(diff.Changes, c =>
            c.Type == PropertyChangeType.Added && c.Name == "Foobar");
        Assert.DoesNotContain(diff.Changes, c =>
            c.Type == PropertyChangeType.Removed && c.Name == "CPU");

        // Now apply to an item that has CPU at position 3 with a value
        var targetItem = new List<ItemProperty>
        {
            new("Specs", "RAM", "16GB"),
            new("Details", "Color", "Black"),
            new("Specs", "CPU", "Intel i7"),
            new("Custom", "Serial", "ABC123"),
        };

        var result = _service.ApplyDiff(targetItem, diff, newProps);

        // Foobar should be at position 1 with the original value preserved
        Assert.Equal(4, result.Count);
        Assert.Equal("Foobar", result[0].Name);
        Assert.Equal("Specs", result[0].Category);
        Assert.Equal("Intel i7", result[0].Value);
        // Template props follow in new order
        Assert.Equal("RAM", result[1].Name);
        Assert.Equal("Color", result[2].Name);
        // Custom prop stays at the end
        Assert.Equal("Serial", result[3].Name);
        Assert.Equal("ABC123", result[3].Value);
    }

    #endregion
}
