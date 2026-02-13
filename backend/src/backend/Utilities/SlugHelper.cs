using System.Text.RegularExpressions;

namespace OneBigHead.Server.Utilities;

/// <summary>
/// Helper class for generating URL-friendly slugs from strings.
/// </summary>
public static partial class SlugHelper
{
    /// <summary>
    /// Generates a URL-friendly slug from a name.
    /// </summary>
    /// <param name="name">The name to convert to a slug.</param>
    /// <param name="defaultValue">The default value if the resulting slug is empty. Defaults to "collection".</param>
    /// <returns>A lowercase, URL-friendly slug.</returns>
    public static string GenerateSlug(string name, string defaultValue = "collection")
    {
        var slug = name.ToLowerInvariant();
        slug = InvalidCharsRegex().Replace(slug, "");
        slug = WhitespaceRegex().Replace(slug, "-");
        slug = MultipleDashRegex().Replace(slug, "-");
        slug = slug.Trim('-');
        return string.IsNullOrEmpty(slug) ? defaultValue : slug;
    }

    [GeneratedRegex("[^a-z0-9\\s-]")]
    private static partial Regex InvalidCharsRegex();

    [GeneratedRegex("\\s+")]
    private static partial Regex WhitespaceRegex();

    [GeneratedRegex("-+")]
    private static partial Regex MultipleDashRegex();
}
