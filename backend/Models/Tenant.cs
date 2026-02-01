using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.Models;

public class Tenant
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    public bool HasCompletedWelcome { get; set; } = false;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Users who have this tenant as their active tenant.
    /// </summary>
    public ICollection<User> ActiveUsers { get; set; } = new List<User>();

    /// <summary>
    /// All user memberships for this tenant. Users can belong to multiple tenants.
    /// </summary>
    public ICollection<TenantUser> TenantUsers { get; set; } = new List<TenantUser>();

    public ICollection<Category> Categories { get; set; } = new List<Category>();
    public ICollection<Collection> Collections { get; set; } = new List<Collection>();
}

