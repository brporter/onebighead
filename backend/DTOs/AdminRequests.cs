using System.ComponentModel.DataAnnotations;

namespace backend.DTOs;

public class TenantSummaryResponse
{
    public int TenantId { get; set; }
    public string Name { get; set; } = string.Empty;
    public int UserCount { get; set; }
    public int CollectionCount { get; set; }
    public int ItemCount { get; set; }
    public int ImageCount { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class UserSummaryResponse
{
    public int UserId { get; set; }
    public string Email { get; set; } = string.Empty;
    public int TenantId { get; set; }
    public string TenantName { get; set; } = string.Empty;
    public string IdentityProvider { get; set; } = string.Empty;
    public bool IsSystemAdministrator { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class SetAdminStatusRequest
{
    public bool IsSystemAdministrator { get; set; }
}

public class SystemTemplateRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string Description { get; set; } = string.Empty;

    public List<ItemTemplatePropertyDto> Properties { get; set; } = new();
}
