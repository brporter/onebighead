namespace backend.DTOs;

// === Requests ===

public class PublishCategoryRequest
{
    public bool IncludeChildren { get; set; }
}

public class PublishCollectionRequest
{
    public bool IncludeChildren { get; set; }
}

public class BulkPublishRequest
{
    public required List<int> ItemIds { get; set; }
}

public class BulkUnpublishRequest
{
    public required List<int> ItemIds { get; set; }
}

// === Responses ===

public class PublishedEntityInfo
{
    public required string Type { get; set; }
    public int Id { get; set; }
    public required string Name { get; set; }
}

public class PublishResponse
{
    public required PublishedEntityInfo Published { get; set; }
    public List<PublishedEntityInfo> Promoted { get; set; } = new();
    public int ChildrenPublished { get; set; }
    public bool RequiresSlugSetup { get; set; }
}

public class BulkPublishResponse
{
    public int PublishedCount { get; set; }
    public List<PublishedEntityInfo> Promoted { get; set; } = new();
    public bool RequiresSlugSetup { get; set; }
}

public class UnpublishResponse
{
    public required PublishedEntityInfo Unpublished { get; set; }
    public int AffectedPublicItems { get; set; }
    public int AffectedPublicCategories { get; set; }
}

public class BulkUnpublishResponse
{
    public int UnpublishedCount { get; set; }
}

public class UnpublishPreviewResponse
{
    public int AffectedPublicItems { get; set; }
    public int AffectedPublicCategories { get; set; }
}
