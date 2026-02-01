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
