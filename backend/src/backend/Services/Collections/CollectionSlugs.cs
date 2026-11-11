using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Utilities;

namespace OneBigHead.Server.Services.Collections;

internal static class CollectionSlugs
{
    public static async Task<string> CreateAsync(AppDbContext context, int workspaceId, string name, int? excludeId = null, CancellationToken cancellationToken = default)
    {
        var generated = SlugHelper.GenerateSlug(name);
        var slug = generated[..Math.Min(generated.Length, 100)].TrimEnd('-');
        if (await context.Collections.AnyAsync(collection => collection.WorkspaceId == workspaceId &&
            collection.Slug == slug && (excludeId == null || collection.Id != excludeId), cancellationToken))
            slug = $"{slug[..Math.Min(slug.Length, 67)].TrimEnd('-')}-{Guid.NewGuid():N}";
        return slug;
    }
}
