using Moq;
using OneBigHead.Server.Services.Images;

namespace OneBigHead.Server.Tests.Services.Images;

public class ImageProcessingPolicyTests
{
    [Theory]
    [InlineData("image/png", RasterImageFormat.Png, "image/png")]
    [InlineData("IMAGE/PNG", RasterImageFormat.Png, "image/png")]
    [InlineData("image/webp", RasterImageFormat.Webp, "image/webp")]
    [InlineData("image/jpeg", RasterImageFormat.Jpeg, "image/jpeg")]
    [InlineData("image/jpg", RasterImageFormat.Jpeg, "image/jpeg")]
    [InlineData("image/avif", RasterImageFormat.Jpeg, "image/jpeg")]
    public void Resizing_UsesTheSelectedEncodingAndDisposesDecodedPixels(string inputType, RasterImageFormat format, string expectedType)
    {
        byte[] original = [1, 2];
        byte[] encoded = [3, 4];
        var image = DecodedImage();
        image.Setup(i => i.ResizeAndEncode(1920, 1440, format)).Returns(encoded);
        var codec = new Mock<IRasterImageCodec>(MockBehavior.Strict);
        codec.Setup(c => c.Decode(original)).Returns(image.Object);

        var (result, type) = new ImageProcessor(codec.Object).ResizeIfNeeded(original, inputType);

        Assert.Same(encoded, result);
        Assert.Equal(expectedType, type);
        image.Verify(i => i.ResizeAndEncode(1920, 1440, format), Times.Once);
        image.Verify(i => i.Dispose(), Times.Once);
    }

    [Fact]
    public void ResizeFailure_KeepsOriginalBytesAndContentTypeAndDisposesPixels()
    {
        byte[] original = [1, 2];
        var image = DecodedImage();
        image.Setup(i => i.ResizeAndEncode(1920, 1440, RasterImageFormat.Jpeg)).Returns((byte[]?)null);
        var codec = Mock.Of<IRasterImageCodec>(c => c.Decode(original) == image.Object);
        var (result, type) = new ImageProcessor(codec).ResizeIfNeeded(original, "image/avif");
        Assert.Same(original, result);
        Assert.Equal("image/avif", type);
        image.Verify(i => i.Dispose(), Times.Once);
    }

    [Fact]
    public void CodecException_PropagatesAfterDecodedPixelsAreDisposed()
    {
        byte[] original = [1, 2];
        var failure = new InvalidOperationException("Native encoder unavailable");
        var image = DecodedImage();
        image.Setup(i => i.ResizeAndEncode(1920, 1440, RasterImageFormat.Jpeg)).Throws(failure);
        var codec = Mock.Of<IRasterImageCodec>(c => c.Decode(original) == image.Object);
        Assert.Same(failure, Assert.Throws<InvalidOperationException>(() => new ImageProcessor(codec).ResizeIfNeeded(original, "image/jpeg")));
        image.Verify(i => i.Dispose(), Times.Once);
    }

    [Fact]
    public void SmallImages_AreNotReencodedAndTheirDecodedPixelsAreDisposed()
    {
        byte[] original = [1, 2];
        var image = DecodedImage();
        image.SetupGet(i => i.Width).Returns(1920);
        image.SetupGet(i => i.Height).Returns(1920);
        var codec = Mock.Of<IRasterImageCodec>(c => c.Decode(original) == image.Object);
        Assert.Same(original, new ImageProcessor(codec).ResizeIfNeeded(original, "image/avif").Data);
        image.Verify(i => i.ResizeAndEncode(It.IsAny<int>(), It.IsAny<int>(), It.IsAny<RasterImageFormat>()), Times.Never);
        image.Verify(i => i.Dispose(), Times.Once);
    }

    [Fact]
    public void GifAnimation_IsPreservedWithoutDecoding()
    {
        byte[] original = [1, 2];
        var codec = new Mock<IRasterImageCodec>(MockBehavior.Strict);
        var (result, type) = new ImageProcessor(codec.Object).ResizeIfNeeded(original, "IMAGE/GIF");
        Assert.Same(original, result);
        Assert.Equal("IMAGE/GIF", type);
        codec.VerifyNoOtherCalls();
    }

    private static Mock<IDecodedRasterImage> DecodedImage()
    {
        var image = new Mock<IDecodedRasterImage>(MockBehavior.Strict);
        image.SetupGet(i => i.Width).Returns(4000);
        image.SetupGet(i => i.Height).Returns(3000);
        image.Setup(i => i.Dispose());
        return image;
    }
}
