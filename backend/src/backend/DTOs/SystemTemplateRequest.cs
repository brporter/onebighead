using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class SystemTemplateRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string Description { get; set; } = string.Empty;

    public List<ItemTemplatePropertyDto> Properties { get; set; } = new();
}