namespace OneBigHead.Server.DTOs;

public class PublicItemDto
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public List<PublicItemPropertyDto> Properties { get; set; } = new();
    public List<PublicItemImageDto> Images { get; set; } = new();
    public int? CategoryId { get; set; }
    public string? CategoryName { get; set; }
    public Guid? TemplateKey { get; set; }
}
