using System.ComponentModel.DataAnnotations;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class TenantMembershipResponse
{
    public int TenantId { get; set; }
    public string TenantName { get; set; } = string.Empty;
    public TenantRole TenantRole { get; set; }
    public bool HasCompletedWelcome { get; set; }
}

public class CreateTenantRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;
}

public class CreateTenantResponse
{
    public int TenantId { get; set; }
    public string TenantName { get; set; } = string.Empty;
    public TenantRole TenantRole { get; set; }
    public bool HasCompletedWelcome { get; set; }
}

public class SwitchTenantResponse
{
    public bool Success { get; set; }
    public int TenantId { get; set; }
    public string TenantName { get; set; } = string.Empty;
}

public class LeaveTenantResponse
{
    public bool Success { get; set; }
}

public class UpdateTenantRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;
}

public class UpdateTenantResponse
{
    public int TenantId { get; set; }
    public string TenantName { get; set; } = string.Empty;
}

/// <summary>
/// Request to set up a new tenant with an optional first collection
/// </summary>
public class SetupTenantRequest
{
    [Required]
    [MaxLength(200)]
    public string TenantName { get; set; } = string.Empty;

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
/// Response from setting up a new tenant
/// </summary>
public class SetupTenantResponse
{
    public int TenantId { get; set; }
    public string TenantName { get; set; } = string.Empty;
    public TenantRole TenantRole { get; set; }
    public int CollectionId { get; set; }
    public string CollectionName { get; set; } = string.Empty;
}
