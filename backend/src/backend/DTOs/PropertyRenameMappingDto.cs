using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class PropertyRenameMappingDto
{
    [Required]
    public string OldCategory { get; set; } = string.Empty;

    [Required]
    public string OldName { get; set; } = string.Empty;

    [Required]
    public string NewCategory { get; set; } = string.Empty;

    [Required]
    public string NewName { get; set; } = string.Empty;
}