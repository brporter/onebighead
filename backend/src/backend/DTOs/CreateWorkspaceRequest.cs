using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class CreateWorkspaceRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;
}