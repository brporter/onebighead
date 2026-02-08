namespace OneBigHead.Server.Services.BulkUpdate;

public record PropertyIdentifier(string Category, string Name);

public record PropertyRenameMapping(string OldCategory, string OldName, string NewCategory, string NewName);

public enum PropertyChangeType
{
    Added,
    Removed,
    Renamed,
    Reordered
}

public record PropertyChange(
    PropertyChangeType Type,
    string Category,
    string Name,
    string? NewCategory = null,
    string? NewName = null);

public record PropertyDiff(List<PropertyChange> Changes);
