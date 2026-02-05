using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace OneBigHead.Server.Models;

public class User
{
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// The user's currently active workspace. This determines which workspace's data
    /// they see and work with in the application.
    /// </summary>
    public int ActiveWorkspaceId { get; set; }

    [Required]
    [MaxLength(320)]
    public string Email { get; set; } = string.Empty;

    public IdentityProvider IdentityProvider { get; set; }

    [MaxLength(255)]
    public string? ProviderSubjectId { get; set; }

    public bool IsSystemAdministrator { get; set; }

    /// <summary>
    /// Whether this user account has been soft-deleted.
    /// Soft-deleted users can be restored by signing back in.
    /// </summary>
    public bool IsDeleted { get; set; }

    /// <summary>
    /// When the user account was soft-deleted.
    /// </summary>
    public DateTime? DeletedAt { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// The date/time when the user accepted the Terms of Service and Privacy Policy.
    /// Null if the user has not yet accepted.
    /// </summary>
    public DateTime? AcceptedTermsAt { get; set; }

    [ForeignKey(nameof(ActiveWorkspaceId))]
    public Workspace? ActiveWorkspace { get; set; }

    /// <summary>
    /// All workspace memberships for this user. A user can belong to multiple workspaces.
    /// </summary>
    public ICollection<WorkspaceUser> WorkspaceMemberships { get; set; } = new List<WorkspaceUser>();

    [NotMapped]
    public bool IsLinked => !string.IsNullOrEmpty(ProviderSubjectId);

    [NotMapped]
    public bool HasAcceptedTerms => AcceptedTermsAt.HasValue;
}
