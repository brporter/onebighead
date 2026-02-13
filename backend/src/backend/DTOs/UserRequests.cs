using System.ComponentModel.DataAnnotations;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class InviteUserRequest
{
    [Required]
    [EmailAddress]
    [MaxLength(320)]
    public string Email { get; set; } = string.Empty;

    public WorkspaceRole Role { get; set; } = WorkspaceRole.Normal;
}

public class UpdateUserRoleRequest
{
    [Required]
    public WorkspaceRole Role { get; set; }
}

public class WorkspaceUserResponse
{
    public int UserId { get; set; }
    public string Email { get; set; } = string.Empty;
    public WorkspaceRole WorkspaceRole { get; set; }
    public bool IsLinked { get; set; }
    public string? IdentityProvider { get; set; }
    public DateTime CreatedAt { get; set; }

    public static WorkspaceUserResponse FromUser(User user, WorkspaceRole role)
    {
        return new WorkspaceUserResponse
        {
            UserId = user.Id,
            Email = user.Email,
            WorkspaceRole = role,
            IsLinked = user.IsLinked,
            IdentityProvider = user.IsLinked ? user.IdentityProvider.ToString() : null,
            CreatedAt = user.CreatedAt
        };
    }

    public static WorkspaceUserResponse FromWorkspaceUser(WorkspaceUser workspaceUser)
    {
        return new WorkspaceUserResponse
        {
            UserId = workspaceUser.UserId,
            Email = workspaceUser.User.Email,
            WorkspaceRole = workspaceUser.WorkspaceRole,
            IsLinked = workspaceUser.User.IsLinked,
            IdentityProvider = workspaceUser.User.IsLinked ? workspaceUser.User.IdentityProvider.ToString() : null,
            CreatedAt = workspaceUser.CreatedAt
        };
    }
}
