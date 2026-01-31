using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace OneBigHead.Server.Models;

public class User
{
    [Key]
    public int Id { get; set; }

    public int TenantId { get; set; }

    [Required]
    [MaxLength(320)]
    public string Email { get; set; } = string.Empty;

    public IdentityProvider IdentityProvider { get; set; }

    [MaxLength(255)]
    public string? ProviderSubjectId { get; set; }

    public bool IsSystemAdministrator { get; set; }

    public TenantRole TenantRole { get; set; } = TenantRole.Normal;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [ForeignKey(nameof(TenantId))]
    public Tenant? Tenant { get; set; }

    [NotMapped]
    public bool IsLinked => !string.IsNullOrEmpty(ProviderSubjectId);
}

