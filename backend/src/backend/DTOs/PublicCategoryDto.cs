namespace OneBigHead.Server.DTOs;

public class PublicCategoryDto
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public int? ParentCategoryId { get; set; }
    public bool IsSystem { get; set; }
    public List<int> ItemTemplateIds { get; set; } = new();
}
