namespace OneBigHead.Server.Services.BulkUpdate;

public record PropertyChange(
    PropertyChangeType Type,
    string Category,
    string Name,
    string? NewCategory = null,
    string? NewName = null);