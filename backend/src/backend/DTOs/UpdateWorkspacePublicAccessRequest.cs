using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

/// <summary>
/// Request to update workspace public access settings (slug and enabled toggle)
/// </summary>
public class UpdateWorkspacePublicAccessRequest
{
    [MaxLength(50)]
    [RegularExpression(@"^[a-z0-9]([a-z0-9]|-(?!-))*[a-z0-9]$", ErrorMessage = "Slug must be lowercase alphanumeric with single hyphens, starting and ending with a letter or number")]
    [MinLength(3)]
    public string? Slug { get; set; }

    public bool IsPublicAccessEnabled { get; set; }
}
