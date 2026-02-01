using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace OneBigHead.Server.Models;

public class User
{
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// The user's currently active tenant. This determines which tenant's data
    /// they see and work with in the application.
    /// </summary>
    public int ActiveTenantId { get; set; }

    [Required]
    [MaxLength(320)]
    public string Email { get; set; } = string.Empty;

    public IdentityProvider IdentityProvider { get; set; }

    [MaxLength(255)]
    public string? ProviderSubjectId { get; set; }

    public bool IsSystemAdministrator { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// The date/time when the user accepted the Terms of Service and Privacy Policy.
    /// Null if the user has not yet accepted.
    /// </summary>
    public DateTime? AcceptedTermsAt { get; set; }

    [ForeignKey(nameof(ActiveTenantId))]
    public Tenant? ActiveTenant { get; set; }

    /// <summary>
    /// All tenant memberships for this user. A user can belong to multiple tenants.
    /// </summary>
    public ICollection<TenantUser> TenantMemberships { get; set; } = new List<TenantUser>();

    [NotMapped]
    public bool IsLinked => !string.IsNullOrEmpty(ProviderSubjectId);

    [NotMapped]
    public bool HasAcceptedTerms => AcceptedTermsAt.HasValue;
}

