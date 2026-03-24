using System.ComponentModel.DataAnnotations;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class CreateCategoryRequest
{
    public int CollectionId { get; set; }

    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string? Description { get; set; }
    public int? ParentCategoryId { get; set; }
    public Visibility Visibility { get; set; } = Visibility.Private;
    public List<int>? ItemTemplateIds { get; set; }
}