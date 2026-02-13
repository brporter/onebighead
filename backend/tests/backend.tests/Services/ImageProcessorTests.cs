using OneBigHead.Server.Services;
using SkiaSharp;

namespace OneBigHead.Server.Tests.Services;

[Trait("Category", "Unit")]
public class ImageProcessorTests
{
    private readonly ImageProcessor _processor = new();

    private static byte[] CreateTestImage(int width, int height, SKEncodedImageFormat format = SKEncodedImageFormat.Jpeg)
    {
        using var bitmap = new SKBitmap(width, height);
        using var canvas = new SKCanvas(bitmap);
        canvas.Clear(SKColors.Blue);
        using var image = SKImage.FromBitmap(bitmap);
        using var data = image.Encode(format, 90);
        return data.ToArray();
    }

    private static byte[] CreateTestGif()
    {
        // Minimal valid GIF89a (1x1 pixel)
        return
        [
            0x47, 0x49, 0x46, 0x38, 0x39, 0x61, // GIF89a
            0x01, 0x00, 0x01, 0x00, // 1x1
            0x00, 0x00, 0x00,       // GCT flag=0, bg=0, aspect=0
            0x2C,                   // Image descriptor
            0x00, 0x00, 0x00, 0x00, // left, top
            0x01, 0x00, 0x01, 0x00, // 1x1
            0x00,                   // no LCT
            0x02, 0x01, 0x01, 0x00, // LZW min code size=2, block
            0x3B                    // trailer
        ];
    }

    [Fact]
    public void ResizeIfNeeded_GifPassthrough_ReturnsUnchanged()
    {
        var gifData = CreateTestGif();

        var (result, contentType) = _processor.ResizeIfNeeded(gifData, "image/gif");

        Assert.Same(gifData, result);
        Assert.Equal("image/gif", contentType);
    }

    [Fact]
    public void ResizeIfNeeded_SmallJpeg_ReturnsOriginalBytes()
    {
        var imageData = CreateTestImage(800, 600);

        var (result, contentType) = _processor.ResizeIfNeeded(imageData, "image/jpeg");

        Assert.Same(imageData, result);
        Assert.Equal("image/jpeg", contentType);
    }

    [Fact]
    public void ResizeIfNeeded_SmallPng_ReturnsOriginalBytes()
    {
        var imageData = CreateTestImage(1920, 1080, SKEncodedImageFormat.Png);

        var (result, contentType) = _processor.ResizeIfNeeded(imageData, "image/png");

        Assert.Same(imageData, result);
        Assert.Equal("image/png", contentType);
    }

    [Fact]
    public void ResizeIfNeeded_ExactBoundary_ReturnsOriginalBytes()
    {
        var imageData = CreateTestImage(1920, 1920);

        var (result, _) = _processor.ResizeIfNeeded(imageData, "image/jpeg");

        Assert.Same(imageData, result);
    }

    [Fact]
    public void ResizeIfNeeded_LargeLandscape_ResizesToMaxWidth()
    {
        var imageData = CreateTestImage(4000, 3000);

        var (result, contentType) = _processor.ResizeIfNeeded(imageData, "image/jpeg");

        Assert.NotSame(imageData, result);
        Assert.Equal("image/jpeg", contentType);

        // Verify output dimensions
        using var decoded = SKBitmap.Decode(result);
        Assert.Equal(1920, decoded.Width);
        Assert.Equal(1440, decoded.Height);
    }

    [Fact]
    public void ResizeIfNeeded_LargePortrait_ResizesToMaxHeight()
    {
        var imageData = CreateTestImage(3000, 4000);

        var (result, contentType) = _processor.ResizeIfNeeded(imageData, "image/jpeg");

        Assert.NotSame(imageData, result);
        Assert.Equal("image/jpeg", contentType);

        using var decoded = SKBitmap.Decode(result);
        Assert.Equal(1440, decoded.Width);
        Assert.Equal(1920, decoded.Height);
    }

    [Fact]
    public void ResizeIfNeeded_LargeSquare_ResizesToMax()
    {
        var imageData = CreateTestImage(3000, 3000);

        var (result, _) = _processor.ResizeIfNeeded(imageData, "image/jpeg");

        Assert.NotSame(imageData, result);

        using var decoded = SKBitmap.Decode(result);
        Assert.Equal(1920, decoded.Width);
        Assert.Equal(1920, decoded.Height);
    }

    [Fact]
    public void ResizeIfNeeded_LargePng_PreservesFormat()
    {
        var imageData = CreateTestImage(3000, 2000, SKEncodedImageFormat.Png);

        var (result, contentType) = _processor.ResizeIfNeeded(imageData, "image/png");

        Assert.Equal("image/png", contentType);

        // Verify it's valid PNG by checking signature
        Assert.True(result.Length >= 8);
        Assert.Equal(0x89, result[0]);
        Assert.Equal(0x50, result[1]); // P
        Assert.Equal(0x4E, result[2]); // N
        Assert.Equal(0x47, result[3]); // G
    }

    [Fact]
    public void ResizeIfNeeded_LargeWebp_ResizesAndPreservesContentType()
    {
        var imageData = CreateTestImage(3840, 2160, SKEncodedImageFormat.Webp);

        var (result, contentType) = _processor.ResizeIfNeeded(imageData, "image/webp");

        Assert.NotSame(imageData, result);
        Assert.Equal("image/webp", contentType);

        using var decoded = SKBitmap.Decode(result);
        Assert.Equal(1920, decoded.Width);
        Assert.Equal(1080, decoded.Height);
    }

    [Fact]
    public void ResizeIfNeeded_PreservesAspectRatio()
    {
        // 16:9 aspect ratio
        var imageData = CreateTestImage(3840, 2160);

        var (result, _) = _processor.ResizeIfNeeded(imageData, "image/jpeg");

        using var decoded = SKBitmap.Decode(result);
        var originalRatio = 3840.0 / 2160.0;
        var resizedRatio = (double)decoded.Width / decoded.Height;
        Assert.Equal(originalRatio, resizedRatio, precision: 2);
    }

    [Fact]
    public void ResizeIfNeeded_OnlyHeightExceedsMax_ResizesCorrectly()
    {
        // Width is fine, but height exceeds 1920
        var imageData = CreateTestImage(1000, 2500);

        var (result, _) = _processor.ResizeIfNeeded(imageData, "image/jpeg");

        Assert.NotSame(imageData, result);

        using var decoded = SKBitmap.Decode(result);
        Assert.Equal(1920, Math.Max(decoded.Width, decoded.Height));
        Assert.True(decoded.Width <= 1920);
        Assert.True(decoded.Height <= 1920);
    }

    [Fact]
    public void ResizeIfNeeded_ResizedImageIsSmaller()
    {
        var imageData = CreateTestImage(4000, 3000);

        var (result, _) = _processor.ResizeIfNeeded(imageData, "image/jpeg");

        Assert.True(result.Length < imageData.Length,
            $"Resized image ({result.Length} bytes) should be smaller than original ({imageData.Length} bytes)");
    }
}
