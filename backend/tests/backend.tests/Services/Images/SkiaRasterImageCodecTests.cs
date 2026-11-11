using OneBigHead.Server.Services.Images;
using SkiaSharp;

namespace OneBigHead.Server.Tests.Services.Images;

public class SkiaRasterImageCodecTests
{
    [Theory]
    [InlineData(RasterImageFormat.Jpeg, SKEncodedImageFormat.Jpeg)]
    [InlineData(RasterImageFormat.Png, SKEncodedImageFormat.Png)]
    [InlineData(RasterImageFormat.Webp, SKEncodedImageFormat.Webp)]
    public void Encoding_ProducesTheRequestedFormatAndSize(RasterImageFormat format, SKEncodedImageFormat expectedFormat)
    {
        using var image = new SkiaRasterImageCodec().Decode(CreatePng());
        Assert.NotNull(image);
        Assert.Equal((32, 24), (image.Width, image.Height));
        var encoded = image.ResizeAndEncode(16, 12, format);
        Assert.NotNull(encoded);
        using var data = SKData.CreateCopy(encoded);
        using var codec = SKCodec.Create(data);
        Assert.Equal(expectedFormat, codec.EncodedFormat);
        Assert.Equal((16, 12), (codec.Info.Width, codec.Info.Height));
        using var pixels = SKBitmap.Decode(codec);
        Assert.InRange(pixels.GetPixel(8, 6).Alpha, format == RasterImageFormat.Jpeg ? 255 : 120, 255);
        if (format != RasterImageFormat.Jpeg) Assert.InRange(pixels.GetPixel(8, 6).Alpha, 120, 135);
    }

    [Fact]
    public void Decoding_RejectsUnrecognizedAndEmptyInput()
    {
        var codec = new SkiaRasterImageCodec();
        Assert.Null(codec.Decode([]));
        Assert.Null(codec.Decode([0, 1, 2, 3]));
    }

    [Fact]
    public void Decoding_RejectsAnImageWhoseHeaderIsValidButPixelDataIsIncomplete()
    {
        var complete = CreatePng();
        var truncated = complete[..(complete.Length / 2)];
        using var data = SKData.CreateCopy(truncated);
        using var native = SKCodec.Create(data);
        Assert.NotNull(native);
        Assert.Null(new SkiaRasterImageCodec().Decode(truncated));
    }

    [Fact]
    public void Resizing_ReturnsNoDataWhenTheNativeResamplerCannotCreateTheRequestedSize()
    {
        using var image = new SkiaRasterImageCodec().Decode(CreatePng());
        Assert.NotNull(image);
        Assert.Null(image.ResizeAndEncode(0, 1, RasterImageFormat.Png));
    }

    [Fact]
    public void Encoding_RejectsAnUndefinedFormat()
    {
        using var image = new SkiaRasterImageCodec().Decode(CreatePng());
        Assert.NotNull(image);
        var error = Assert.Throws<ArgumentOutOfRangeException>(() => image.ResizeAndEncode(16, 12, (RasterImageFormat)99));
        Assert.Equal("format", error.ParamName);
    }

    private static byte[] CreatePng()
    {
        using var bitmap = new SKBitmap(32, 24);
        bitmap.Erase(SKColors.Blue.WithAlpha(128));
        using var image = SKImage.FromBitmap(bitmap);
        using var data = image.Encode(SKEncodedImageFormat.Png, 100);
        return data.ToArray();
    }
}
