namespace OneBigHead.Server.Authentication;

/// <summary>
/// Constants for custom JWT claim names used throughout the application.
/// </summary>
public static class ClaimNames
{
    /// <summary>
    /// The claim name for the user's active workspace ID.
    /// </summary>
    public const string WorkspaceId = "workspace_id";

    /// <summary>
    /// The claim name for the user's role within the workspace.
    /// </summary>
    public const string WorkspaceRole = "workspace_role";

    /// <summary>
    /// The claim name for the identity provider used for authentication.
    /// </summary>
    public const string Provider = "provider";
}
