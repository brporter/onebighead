using System.ComponentModel.DataAnnotations;

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
    public bool IsPublic { get; set; } = false;
}

public class UpdateCollectionRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string? Description { get; set; }

    [MaxLength(500)]
    public string? HeroImageUrl { get; set; }
    public bool IsPublic { get; set; } = false;
}

public class SetupCollectionRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string? Description { get; set; }

    [MaxLength(500)]
    public string? HeroImageUrl { get; set; }
    
    public bool IsPublic { get; set; } = false;

    /// <summary>
    /// The theme ID to apply to the new collection.
    /// </summary>
    [Required]
    public int ThemeId { get; set; }
}
