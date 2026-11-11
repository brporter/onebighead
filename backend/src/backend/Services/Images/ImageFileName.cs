namespace OneBigHead.Server.Services.Images;

public static class ImageFileName
{
    private const int MaxLength = 200;
    private const string UnsafeCharacters = "<>:\"/\\|?*";

    public static string Sanitize(string? fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName)) return "image";

        // Browsers can submit Windows paths even when the server runs on Unix.
        var name = Path.GetFileName(fileName.Replace('\\', '/'));
        var sanitized = new string(name.Where(character => character >= 32 && character != 127)
            .Select(character => UnsafeCharacters.Contains(character) ? '_' : character).ToArray()).Trim('.', ' ');
        if (sanitized.Length > MaxLength)
        {
            var extension = Path.GetExtension(sanitized);
            sanitized = extension.Length >= MaxLength
                ? sanitized[..MaxLength]
                : sanitized[..(MaxLength - extension.Length)] + extension;
        }
        return string.IsNullOrWhiteSpace(sanitized) ? "image" : sanitized;
    }
}
