using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class PropertyIdentifierDto
{
    [Required]
    public string Category { get; set; } = string.Empty;

    [Required]
    public string Name { get; set; } = string.Empty;
}