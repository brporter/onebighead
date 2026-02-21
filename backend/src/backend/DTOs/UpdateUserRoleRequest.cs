using System.ComponentModel.DataAnnotations;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class UpdateUserRoleRequest
{
    [Required]
    public WorkspaceRole Role { get; set; }
}