using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Publishing;

internal static class PublicationConsent
{
    public static bool IsResolved(PublishRequirement requirement, List<PublishResolution> resolutions) => requirement switch
    {
        WorkspaceSlugRequiredRequirement => resolutions.OfType<WorkspaceSlugResolution>().Count() == 1 &&
            IsValidSlug(resolutions.OfType<WorkspaceSlugResolution>().Single().Slug),
        CollectionNotPublicRequirement collection => resolutions.OfType<CollectionNotPublicResolution>().Any(resolution => resolution.CollectionId == collection.CollectionId),
        CategoryNotPublicRequirement category => resolutions.OfType<CategoryNotPublicResolution>().Any(resolution => resolution.CategoryId == category.CategoryId),
        UnpublishWillHideChildrenRequirement impact => resolutions.OfType<UnpublishWillHideChildrenResolution>()
            .Any(resolution => resolution.EntityType == impact.EntityType && resolution.EntityId == impact.EntityId &&
                resolution.AffectedPublicItems == impact.AffectedPublicItems && resolution.AffectedPublicCategories == impact.AffectedPublicCategories),
        _ => false
    };

    public static bool IsValidSlug(string? slug) => slug is { Length: >= 3 and <= 50 } && slug[0] != '-' && slug[^1] != '-' &&
        !slug.Contains("--", StringComparison.Ordinal) && slug.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');
}
