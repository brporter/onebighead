using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class CreateSupportRequestDto
{
    [Required]
    [MaxLength(200)]
    public string Subject { get; set; } = string.Empty;

    [Required]
    [MaxLength(4000)]
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Required for anonymous users, optional for logged-in users.
    /// </summary>
    [MaxLength(320)]
    [EmailAddress]
    public string? Email { get; set; }
}