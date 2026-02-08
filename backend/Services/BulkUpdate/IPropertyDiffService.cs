using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.BulkUpdate;

public interface IPropertyDiffService
{
    PropertyDiff ComputeDiff(
        List<PropertyIdentifier> oldProps,
        List<PropertyIdentifier> newProps,
        List<PropertyRenameMapping>? renameMappings = null);

    List<ItemProperty> ApplyDiff(
        List<ItemProperty> targetProperties,
        PropertyDiff diff,
        List<PropertyIdentifier> newPropertyOrder);
}
