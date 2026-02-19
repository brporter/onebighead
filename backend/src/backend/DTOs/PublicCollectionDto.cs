namespace OneBigHead.Server.DTOs;

public class PublicCollectionDto
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? HeroImageUrl { get; set; }
    public string Slug { get; set; } = string.Empty;
}
