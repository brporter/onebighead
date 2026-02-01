using System.ComponentModel.DataAnnotations;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class InviteUserRequest
{
    [Required]
    [EmailAddress]
    [MaxLength(320)]
    public string Email { get; set; } = string.Empty;

    public TenantRole Role { get; set; } = TenantRole.Normal;
}

public class UpdateUserRoleRequest
{
    [Required]
    public TenantRole Role { get; set; }
}

public class TenantUserResponse
{
    public int UserId { get; set; }
    public string Email { get; set; } = string.Empty;
    public TenantRole TenantRole { get; set; }
    public bool IsLinked { get; set; }
    public string? IdentityProvider { get; set; }
    public DateTime CreatedAt { get; set; }

    public static TenantUserResponse FromUser(User user, TenantRole role)
    {
        return new TenantUserResponse
        {
            UserId = user.Id,
            Email = user.Email,
            TenantRole = role,
            IsLinked = user.IsLinked,
            IdentityProvider = user.IsLinked ? user.IdentityProvider.ToString() : null,
            CreatedAt = user.CreatedAt
        };
    }

    public static TenantUserResponse FromTenantUser(TenantUser tenantUser)
    {
        return new TenantUserResponse
        {
            UserId = tenantUser.UserId,
            Email = tenantUser.User.Email,
            TenantRole = tenantUser.TenantRole,
            IsLinked = tenantUser.User.IsLinked,
            IdentityProvider = tenantUser.User.IsLinked ? tenantUser.User.IdentityProvider.ToString() : null,
            CreatedAt = tenantUser.CreatedAt
        };
    }
}
