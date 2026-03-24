using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class UpdateWorkspaceRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(50)]
    [RegularExpression(@"^[a-z0-9]([a-z0-9]|-(?!-))*[a-z0-9]$", ErrorMessage = "Slug must be lowercase alphanumeric with single hyphens, starting and ending with a letter or number")]
    [MinLength(3)]
    public string? Slug { get; set; }
}