using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.Models;

public class Workspace
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    public bool HasCompletedWelcome { get; set; } = false;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Soft delete flag. Deleted workspaces are not permanently removed.
    /// </summary>
    public bool IsDeleted { get; set; } = false;

    public DateTime? DeletedAt { get; set; }

    /// <summary>
    /// The user who soft-deleted this workspace.
    /// </summary>
    public int? DeletedByUserId { get; set; }

    /// <summary>
    /// Users who have this workspace as their active workspace.
    /// </summary>
    public ICollection<User> ActiveUsers { get; set; } = new List<User>();

    /// <summary>
    /// All user memberships for this workspace. Users can belong to multiple workspaces.
    /// </summary>
    public ICollection<WorkspaceUser> WorkspaceUsers { get; set; } = new List<WorkspaceUser>();

    public ICollection<Category> Categories { get; set; } = new List<Category>();
    public ICollection<Collection> Collections { get; set; } = new List<Collection>();
}
