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