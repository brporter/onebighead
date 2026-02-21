using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Models;

[Trait("Category", "Unit")]
public class ItemImageTests
{
    [Fact]
    public void ItemImage_Record_StoresValues()
    {
        // Act
        var image = new ItemImage("https://example.com/img.jpg", "Alt text");

        // Assert
        Assert.Equal("https://example.com/img.jpg", image.Url);
        Assert.Equal("Alt text", image.Alt);
    }

    [Fact]
    public void ItemImage_Equality_WorksCorrectly()
    {
        // Arrange
        var img1 = new ItemImage("url", "alt");
        var img2 = new ItemImage("url", "alt");
        var img3 = new ItemImage("url", "different");

        // Assert
        Assert.Equal(img1, img2);
        Assert.NotEqual(img1, img3);
    }
}