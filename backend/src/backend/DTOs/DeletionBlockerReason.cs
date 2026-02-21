namespace OneBigHead.Server.DTOs;

/// <summary>
/// Reasons why a user cannot immediately delete their account.
/// </summary>
public enum DeletionBlockerReason
{
    /// <summary>No blocker - user can leave this workspace freely.</summary>
    None,
    /// <summary>User is the only member of this workspace.</summary>
    SoleUser,
    /// <summary>User is the only admin in a workspace with other users.</summary>
    SoleAdmin
}