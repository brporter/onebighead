using System.ComponentModel.DataAnnotations;

namespace backend.Models;

public class Tenant
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<User> Users { get; set; } = new List<User>();
    public ICollection<Category> Categories { get; set; } = new List<Category>();
    public ICollection<Collection> Collections { get; set; } = new List<Collection>();
}

