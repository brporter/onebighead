using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class UpdateCategoryRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string? Description { get; set; }
    public int? ParentCategoryId { get; set; }
    public List<int>? ItemTemplateIds { get; set; }
}