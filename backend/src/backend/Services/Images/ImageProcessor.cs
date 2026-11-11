namespace OneBigHead.Server.Services.Images;

/// <summary>Image sizing and output-format policy, independent of the native codec.</summary>
public sealed class ImageProcessor(IRasterImageCodec codec) : IImageProcessor
{
    private const int MaxDimension = 1920;

    public (byte[] Data, string ContentType) ResizeIfNeeded(byte[] imageData, string contentType)
    {
        // Re-encoding a GIF would discard its animation.
        if (contentType.Equals("image/gif", StringComparison.OrdinalIgnoreCase))
            return (imageData, contentType);

        using var image = codec.Decode(imageData);
        if (image is null || (image.Width <= MaxDimension && image.Height <= MaxDimension))
            return (imageData, contentType);

        var scale = (double)MaxDimension / Math.Max(image.Width, image.Height);
        var width = Math.Max(1, (int)Math.Round(image.Width * scale));
        var height = Math.Max(1, (int)Math.Round(image.Height * scale));
        var (format, outputContentType) = contentType.ToLowerInvariant() switch
        {
            "image/png" => (RasterImageFormat.Png, "image/png"),
            "image/webp" => (RasterImageFormat.Webp, "image/webp"),
            _ => (RasterImageFormat.Jpeg, "image/jpeg")
        };

        var result = image.ResizeAndEncode(width, height, format);
        // Retain both original bytes and original type if the codec cannot resize.
        return result is null ? (imageData, contentType) : (result, outputContentType);
    }
}
