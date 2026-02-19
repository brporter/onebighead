using System.ComponentModel.DataAnnotations;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class WorkspaceMembershipResponse
{
    public int WorkspaceId { get; set; }
    public string WorkspaceName { get; set; } = string.Empty;
    public WorkspaceRole WorkspaceRole { get; set; }
    public bool HasCompletedWelcome { get; set; }
}

public class CreateWorkspaceRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;
}

public class CreateWorkspaceResponse
{
    public int WorkspaceId { get; set; }
    public string WorkspaceName { get; set; } = string.Empty;
    public WorkspaceRole WorkspaceRole { get; set; }
    public bool HasCompletedWelcome { get; set; }
}

public class SwitchWorkspaceResponse
{
    public bool Success { get; set; }
    public int WorkspaceId { get; set; }
    public string WorkspaceName { get; set; } = string.Empty;
}

public class LeaveWorkspaceResponse
{
    public bool Success { get; set; }
}

public class UpdateWorkspaceRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;
}

public class UpdateWorkspaceResponse
{
    public int WorkspaceId { get; set; }
    public string WorkspaceName { get; set; } = string.Empty;
}

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

/// <summary>
/// Response from setting up a new workspace
/// </summary>
public class SetupWorkspaceResponse
{
    public int WorkspaceId { get; set; }
    public string WorkspaceName { get; set; } = string.Empty;
    public WorkspaceRole WorkspaceRole { get; set; }
    public int CollectionId { get; set; }
    public string CollectionName { get; set; } = string.Empty;
}

/// <summary>
/// A soft-deleted workspace that the user can restore
/// </summary>
public class RestorableWorkspaceResponse
{
    public int WorkspaceId { get; set; }
    public string Name { get; set; } = string.Empty;
    public DateTime DeletedAt { get; set; }
    public int DaysRemaining { get; set; }
    public RestorableWorkspaceStats Stats { get; set; } = new();
}

public class RestorableWorkspaceStats
{
    public int CollectionCount { get; set; }
    public int ItemCount { get; set; }
    public int CategoryCount { get; set; }
    public int ImageCount { get; set; }
}

/// <summary>
/// Request to restore multiple soft-deleted workspaces
/// </summary>
public class RestoreWorkspacesRequest
{
    public List<int> WorkspaceIds { get; set; } = new();
}

/// <summary>
/// Response from restoring workspaces
/// </summary>
public class RestoreWorkspacesResponse
{
    public List<int> RestoredWorkspaceIds { get; set; } = new();
    public int ActiveWorkspaceId { get; set; }
}

/// <summary>
/// Response from restoring a single workspace
/// </summary>
public class RestoreWorkspaceResponse
{
    public int WorkspaceId { get; set; }
    public string Name { get; set; } = string.Empty;
}

