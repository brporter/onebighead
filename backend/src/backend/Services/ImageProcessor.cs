using SkiaSharp;

namespace OneBigHead.Server.Services;

public class ImageProcessor : IImageProcessor
{
    private const int MaxDimension = 1920;
    private const int JpegQuality = 85;
    private const int WebpQuality = 85;

    public (byte[] Data, string ContentType) ResizeIfNeeded(byte[] imageData, string contentType)
    {
        // Pass GIFs through unchanged to preserve animation
        if (contentType.Equals("image/gif", StringComparison.OrdinalIgnoreCase))
            return (imageData, contentType);

        using var original = SKBitmap.Decode(imageData);
        if (original == null)
            return (imageData, contentType);

        // If both dimensions are within the limit, return original unchanged (no re-encode)
        if (original.Width <= MaxDimension && original.Height <= MaxDimension)
            return (imageData, contentType);

        // Calculate new dimensions preserving aspect ratio
        var (newWidth, newHeight) = CalculateScaledDimensions(original.Width, original.Height);

        var destInfo = new SKImageInfo(newWidth, newHeight, original.ColorType, original.AlphaType);
        using var resized = original.Resize(destInfo, new SKSamplingOptions(SKCubicResampler.Mitchell));
        if (resized == null)
            return (imageData, contentType);

        using var image = SKImage.FromBitmap(resized);
        var format = MapContentTypeToFormat(contentType);
        var quality = GetQuality(format);

        using var encoded = image.Encode(format, quality);
        return (encoded.ToArray(), contentType);
    }

    private static (int Width, int Height) CalculateScaledDimensions(int width, int height)
    {
        var longestSide = Math.Max(width, height);
        var scale = (double)MaxDimension / longestSide;

        return ((int)Math.Round(width * scale), (int)Math.Round(height * scale));
    }

    private static SKEncodedImageFormat MapContentTypeToFormat(string contentType)
    {
        return contentType.ToLowerInvariant() switch
        {
            "image/jpeg" or "image/jpg" => SKEncodedImageFormat.Jpeg,
            "image/png" => SKEncodedImageFormat.Png,
            "image/webp" => SKEncodedImageFormat.Webp,
            _ => SKEncodedImageFormat.Jpeg
        };
    }

    private static int GetQuality(SKEncodedImageFormat format)
    {
        return format switch
        {
            SKEncodedImageFormat.Jpeg => JpegQuality,
            SKEncodedImageFormat.Webp => WebpQuality,
            _ => 100 // PNG uses lossless compression; quality param is ignored
        };
    }
}
