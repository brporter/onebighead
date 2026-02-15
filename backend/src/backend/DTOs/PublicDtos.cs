namespace OneBigHead.Server.DTOs;

public class PublicWorkspaceDto
{
    public string Name { get; set; } = string.Empty;
    public string Slug { get; set; } = string.Empty;
}

public class PublicCollectionDto
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? HeroImageUrl { get; set; }
    public string Slug { get; set; } = string.Empty;
}

public class PublicCategoryDto
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public int? ParentCategoryId { get; set; }
    public bool IsSystem { get; set; }
    public List<int> ItemTemplateIds { get; set; } = new();
}

public class PublicItemSummaryDto
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string? PrimaryImageUrl { get; set; }
    public int? CategoryId { get; set; }
}

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

public class PublicItemPropertyDto
{
    public string Category { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
}

public class PublicItemImageDto
{
    public string Url { get; set; } = string.Empty;
    public string? Alt { get; set; }
}

public class PublicCollectionDetailDto
{
    public PublicCollectionDto Collection { get; set; } = new();
    public List<PublicCategoryDto> Categories { get; set; } = new();
}
