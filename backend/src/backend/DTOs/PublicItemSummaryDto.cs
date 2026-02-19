namespace OneBigHead.Server.DTOs;

public class PublicItemSummaryDto
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string? PrimaryImageUrl { get; set; }
    public int? CategoryId { get; set; }
}
