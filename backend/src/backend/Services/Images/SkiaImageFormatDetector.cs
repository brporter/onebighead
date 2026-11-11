using SkiaSharp;

namespace OneBigHead.Server.Services.Images;

public sealed class SkiaImageFormatDetector : IImageFormatDetector
{
    private static readonly Dictionary<SKEncodedImageFormat, string> AllowedFormats = new()
    {
        { SKEncodedImageFormat.Jpeg, "image/jpeg" },
        { SKEncodedImageFormat.Png, "image/png" },
        { SKEncodedImageFormat.Gif, "image/gif" },
        { SKEncodedImageFormat.Webp, "image/webp" },
        { SKEncodedImageFormat.Avif, "image/avif" },
    };

    public string? Detect(byte[] data)
    {
        using var encoded = SKData.CreateCopy(data);
        using var codec = SKCodec.Create(encoded);
        return codec is null ? null : AllowedFormats.GetValueOrDefault(codec.EncodedFormat);
    }
}
