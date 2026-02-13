using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class WorkspaceSummaryResponse
{
    public int WorkspaceId { get; set; }
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
    public int WorkspaceId { get; set; }
    public string WorkspaceName { get; set; } = string.Empty;
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
