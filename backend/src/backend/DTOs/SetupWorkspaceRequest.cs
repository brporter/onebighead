using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

/// <summary>
/// Request to set up a new workspace with an optional first collection
/// </summary>
public class SetupWorkspaceRequest
{
    [Required]
    [MaxLength(200)]
    public string WorkspaceName { get; set; } = string.Empty;

    /// <summary>
    /// Optional collection name. If not provided, a default "My Collection" will be created.
    /// </summary>
    [MaxLength(200)]
    public string? CollectionName { get; set; }

    /// <summary>
    /// Optional collection description
    /// </summary>
    [MaxLength(2000)]
    public string? CollectionDescription { get; set; }

    /// <summary>
    /// Optional theme ID to apply to the collection. If not provided, the General theme will be used.
    /// </summary>
    public int? ThemeId { get; set; }
}