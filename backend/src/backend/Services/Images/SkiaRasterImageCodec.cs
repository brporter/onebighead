using SkiaSharp;

namespace OneBigHead.Server.Services.Images;

/// <summary>Owns native decoding, resampling, encoding and pixel-buffer disposal.</summary>
public sealed class SkiaRasterImageCodec : IRasterImageCodec
{
    public IDecodedRasterImage? Decode(byte[] data)
    {
        using var encoded = SKData.CreateCopy(data);
        using var codec = SKCodec.Create(encoded);
        if (codec is null) return null;

        var bitmap = new SKBitmap(codec.Info);
        if (codec.GetPixels(bitmap.Info, bitmap.GetPixels()) != SKCodecResult.Success)
        {
            bitmap.Dispose();
            return null;
        }
        return new DecodedImage(bitmap);
    }

    private sealed class DecodedImage(SKBitmap bitmap) : IDecodedRasterImage
    {
        public int Width => bitmap.Width;
        public int Height => bitmap.Height;

        public byte[]? ResizeAndEncode(int width, int height, RasterImageFormat format)
        {
            var info = new SKImageInfo(width, height, bitmap.ColorType, bitmap.AlphaType);
            using var resized = bitmap.Resize(info, new SKSamplingOptions(SKCubicResampler.Mitchell));
            if (resized is null) return null;

            var (encoding, quality) = format switch
            {
                RasterImageFormat.Jpeg => (SKEncodedImageFormat.Jpeg, 85),
                RasterImageFormat.Png => (SKEncodedImageFormat.Png, 100),
                RasterImageFormat.Webp => (SKEncodedImageFormat.Webp, 85),
                _ => throw new ArgumentOutOfRangeException(nameof(format))
            };
            using var image = SKImage.FromBitmap(resized);
            using var encoded = image.Encode(encoding, quality);
            return encoded.ToArray();
        }

        public void Dispose() => bitmap.Dispose();
    }
}
