using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class UpdateWorkspaceRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;
}