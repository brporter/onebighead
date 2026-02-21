using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class ItemTemplatePropertyDto
{
    [Required]
    [MaxLength(100)]
    public string Category { get; set; } = string.Empty;

    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = string.Empty;
}