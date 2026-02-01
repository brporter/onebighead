using System.ComponentModel.DataAnnotations.Schema;

namespace OneBigHead.Server.Models;

public class TenantUser
{
    public int UserId { get; set; }
    public int TenantId { get; set; }
    public TenantRole TenantRole { get; set; } = TenantRole.Normal;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [ForeignKey(nameof(UserId))]
    public User User { get; set; } = null!;

    [ForeignKey(nameof(TenantId))]
    public Tenant Tenant { get; set; } = null!;
}
