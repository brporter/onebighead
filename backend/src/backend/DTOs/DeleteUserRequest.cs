using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

/// <summary>
/// Request to delete a user account.
/// </summary>
public class DeleteUserRequest
{
    /// <summary>
    /// User must confirm their email address to delete their account.
    /// </summary>
    [Required]
    public string ConfirmEmail { get; set; } = string.Empty;

    /// <summary>
    /// Actions to take on each workspace that requires resolution.
    /// </summary>
    public List<WorkspaceActionRequest> WorkspaceActions { get; set; } = new();
}