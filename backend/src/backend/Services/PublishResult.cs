namespace OneBigHead.Server.Services;

public class PublishedEntityInfo
{
    public required string Type { get; set; }
    public int Id { get; set; }
    public required string Name { get; set; }
}

public class PublishResult
{
    public required PublishedEntityInfo Published { get; set; }
    public List<PublishedEntityInfo> Promoted { get; set; } = new();
    public int ChildrenPublished { get; set; }
}

public class UnpublishPreview
{
    public int AffectedPublicItems { get; set; }
    public int AffectedPublicCategories { get; set; }
}
