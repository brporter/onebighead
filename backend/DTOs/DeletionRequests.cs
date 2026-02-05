using System.ComponentModel.DataAnnotations;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

/// <summary>
/// Statistics about a tenant's data, used for deletion confirmation.
/// </summary>
public class TenantStatsResponse
{
    public int TenantId { get; set; }
    public string TenantName { get; set; } = string.Empty;
    public int CollectionCount { get; set; }
    public int CategoryCount { get; set; }
    public int ItemCount { get; set; }
    public int ImageCount { get; set; }
    public int UserCount { get; set; }
    public int AdminCount { get; set; }
}

/// <summary>
/// Result of a tenant deletion operation.
/// </summary>
public class TenantDeletionResponse
{
    public bool Success { get; set; }
    /// <summary>
    /// The new active tenant ID for the user, if they were switched to another tenant.
    /// </summary>
    public int? NewActiveTenantId { get; set; }
    /// <summary>
    /// True if the user account was also soft-deleted (single-tenant admin scenario).
    /// Frontend should log out and redirect to homepage.
    /// </summary>
    public bool UserSoftDeleted { get; set; }
}

/// <summary>
/// Information about a user's deletion blockers and requirements.
/// </summary>
public class UserDeletionInfoResponse
{
    public int UserId { get; set; }
    public string Email { get; set; } = string.Empty;
    public List<TenantMembershipDeletionInfo> TenantMemberships { get; set; } = new();
    public int TenantsRequiringAction { get; set; }
    public bool CanDeleteImmediately { get; set; }
}

/// <summary>
/// Information about a specific tenant membership for deletion purposes.
/// </summary>
public class TenantMembershipDeletionInfo
{
    public int TenantId { get; set; }
    public string TenantName { get; set; } = string.Empty;
    public TenantRole Role { get; set; }
    public bool IsOnlyUser { get; set; }
    public bool IsOnlyAdmin { get; set; }
    public int UserCount { get; set; }
    public bool CanLeave { get; set; }
    public DeletionBlockerReason BlockerReason { get; set; }
    /// <summary>
    /// Other users in the tenant, for admin transfer selection.
    /// </summary>
    public List<UserBasicInfo> OtherUsers { get; set; } = new();
}

/// <summary>
/// Basic user information for admin transfer selection.
/// </summary>
public class UserBasicInfo
{
    public int UserId { get; set; }
    public string Email { get; set; } = string.Empty;
}

/// <summary>
/// Reasons why a user cannot immediately delete their account.
/// </summary>
public enum DeletionBlockerReason
{
    /// <summary>No blocker - user can leave this tenant freely.</summary>
    None,
    /// <summary>User is the only member of this tenant.</summary>
    SoleUser,
    /// <summary>User is the only admin in a tenant with other users.</summary>
    SoleAdmin
}

/// <summary>
/// Types of actions a user can take on a tenant during account deletion.
/// </summary>
public enum TenantActionType
{
    /// <summary>Delete the tenant (when user is sole member).</summary>
    Delete,
    /// <summary>Transfer admin role to another user.</summary>
    Transfer
}

/// <summary>
/// Request to delete a user account.
/// </summary>
public class DeleteUserRequest
{
    /// <summary>
    /// User must confirm their email address to delete their account.
    /// </summary>
    [Required]
    public string ConfirmEmail { get; set; } = string.Empty;

    /// <summary>
    /// Actions to take on each tenant that requires resolution.
    /// </summary>
    public List<TenantActionRequest> TenantActions { get; set; } = new();
}

/// <summary>
/// Action to take on a specific tenant during account deletion.
/// </summary>
public class TenantActionRequest
{
    public int TenantId { get; set; }
    public TenantActionType Action { get; set; }
    /// <summary>
    /// User ID to transfer admin role to (required when Action is Transfer).
    /// </summary>
    public int? TransferToUserId { get; set; }
}

/// <summary>
/// Result of a user account deletion operation.
/// </summary>
public class DeleteUserResponse
{
    public bool Success { get; set; }
    public string? Error { get; set; }
}

/// <summary>
/// Request to transfer admin role to another user.
/// </summary>
public class TransferAdminRequest
{
    [Required]
    public int NewAdminUserId { get; set; }
}

/// <summary>
/// Result of an admin transfer operation.
/// </summary>
public class TransferAdminResponse
{
    public bool Success { get; set; }
    public string? Error { get; set; }
}
