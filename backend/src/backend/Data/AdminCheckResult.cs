namespace OneBigHead.Server.Data;

/// <summary>
/// Result of an atomic admin check operation.
/// </summary>
public enum AdminCheckResult
{
    Success,
    UserNotFound,
    WouldRemoveLastAdmin
}