using OneBigHead.Server.Services.Images;

namespace OneBigHead.Server.Tests.Services;

public class ImageFileNameTests
{
    [Theory]
    [InlineData(null, "image")]
    [InlineData("", "image")]
    [InlineData(" \t ", "image")]
    [InlineData("..  ", "image")]
    [InlineData("\0\u007f", "image")]
    [InlineData("/", "image")]
    [InlineData("../photos/image.png", "image.png")]
    [InlineData("C:\\Users\\Owner\\photo.png", "photo.png")]
    [InlineData(". photo.png . ", "photo.png")]
    [InlineData("photo\0\t\u007f.png", "photo.png")]
    [InlineData("photo:*?\"<>|.png", "photo_______.png")]
    [InlineData("写真.png", "写真.png")]
    public void Sanitize_RemovesPathsAndUnsafeCharactersAcrossPlatforms(string? input, string expected) =>
        Assert.Equal(expected, ImageFileName.Sanitize(input));

    [Fact]
    public void Limit_PreservesShortExtensionsAndHandlesOversizedExtensions()
    {
        var exact = new string('a', 196) + ".png";
        Assert.Equal(exact, ImageFileName.Sanitize(exact));
        Assert.Equal(exact, ImageFileName.Sanitize(new string('a', 300) + ".png"));
        Assert.Equal(new string('a', 200), ImageFileName.Sanitize(new string('a', 201)));
        var longExtension = "photo." + new string('x', 250);
        Assert.Equal(longExtension[..200], ImageFileName.Sanitize(longExtension));
    }
}
