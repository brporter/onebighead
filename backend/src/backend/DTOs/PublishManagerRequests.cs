using System.Text.Json.Serialization;

namespace backend.DTOs;

// === Shared Types ===

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum PublishAction
{
    Publish,
    Unpublish,
}

public class EntityRef
{
    public required string Type { get; set; } // "item", "category", "collection"
    public int Id { get; set; }
}

public class ChangedEntityInfo
{
    public required string Type { get; set; }
    public int Id { get; set; }
    public required string Name { get; set; }
}

// === Preflight ===

public class PreflightRequest
{
    public PublishAction Action { get; set; }
    public required List<EntityRef> Entities { get; set; }
}

public class PreflightResponse
{
    public bool Ready { get; set; }
    public List<PublishRequirement> Requirements { get; set; } = new();
}

[JsonPolymorphic(TypeDiscriminatorPropertyName = "kind")]
[JsonDerivedType(typeof(WorkspaceSlugRequiredRequirement), "workspace-slug-required")]
[JsonDerivedType(typeof(CollectionNotPublicRequirement), "collection-not-public")]
[JsonDerivedType(typeof(CategoryNotPublicRequirement), "category-not-public")]
[JsonDerivedType(typeof(UnpublishWillHideChildrenRequirement), "unpublish-will-hide-children")]
public abstract class PublishRequirement { }

public class WorkspaceSlugRequiredRequirement : PublishRequirement
{
    public int WorkspaceId { get; set; }
    public required string WorkspaceName { get; set; }
}

public class CollectionNotPublicRequirement : PublishRequirement
{
    public int CollectionId { get; set; }
    public required string CollectionName { get; set; }
}

public class CategoryNotPublicRequirement : PublishRequirement
{
    public int CategoryId { get; set; }
    public required string CategoryName { get; set; }
}

public class UnpublishWillHideChildrenRequirement : PublishRequirement
{
    public required string EntityType { get; set; }
    public int EntityId { get; set; }
    public required string EntityName { get; set; }
    public int AffectedPublicItems { get; set; }
    public int AffectedPublicCategories { get; set; }
}

// === Execute ===

public class ExecuteRequest
{
    public PublishAction Action { get; set; }
    public required List<EntityRef> Entities { get; set; }
    public List<PublishResolution> Resolutions { get; set; } = new();
}

[JsonPolymorphic(TypeDiscriminatorPropertyName = "kind")]
[JsonDerivedType(typeof(WorkspaceSlugResolution), "workspace-slug-required")]
[JsonDerivedType(typeof(CollectionNotPublicResolution), "collection-not-public")]
[JsonDerivedType(typeof(CategoryNotPublicResolution), "category-not-public")]
[JsonDerivedType(typeof(UnpublishWillHideChildrenResolution), "unpublish-will-hide-children")]
public abstract class PublishResolution { }

public class WorkspaceSlugResolution : PublishResolution
{
    public required string Slug { get; set; }
}

public class CollectionNotPublicResolution : PublishResolution
{
    public int CollectionId { get; set; }
}

public class CategoryNotPublicResolution : PublishResolution
{
    public int CategoryId { get; set; }
}

public class UnpublishWillHideChildrenResolution : PublishResolution
{
    public required string EntityType { get; set; }
    public int EntityId { get; set; }
}

public class ExecuteResponse
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public List<ChangedEntityInfo> Changed { get; set; } = new();
    public List<ChangedEntityInfo> Promoted { get; set; } = new();
    public string? WorkspaceSlugSet { get; set; }
    public List<PublishRequirement>? Requirements { get; set; }
}
