namespace OneBigHead.Server.DTOs;

public class PublicCollectionDetailDto
{
    public PublicCollectionDto Collection { get; set; } = new();
    public List<PublicCategoryDto> Categories { get; set; } = new();
}
