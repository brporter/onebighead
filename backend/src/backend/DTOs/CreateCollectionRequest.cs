using System.ComponentModel.DataAnnotations;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class CreateCollectionRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string? Description { get; set; }

    [MaxLength(500)]
    public string? HeroImageUrl { get; set; }
    public Visibility Visibility { get; set; } = Visibility.Private;
}