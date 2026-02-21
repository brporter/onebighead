using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Models;

[Trait("Category", "Unit")]
public class ItemPropertyTests
{
    [Fact]
    public void ItemProperty_Record_StoresValues()
    {
        // Act
        var property = new ItemProperty("Category", "Name", "Value");

        // Assert
        Assert.Equal("Category", property.Category);
        Assert.Equal("Name", property.Name);
        Assert.Equal("Value", property.Value);
    }

    [Fact]
    public void ItemProperty_Equality_WorksCorrectly()
    {
        // Arrange
        var prop1 = new ItemProperty("Cat", "Name", "Value");
        var prop2 = new ItemProperty("Cat", "Name", "Value");
        var prop3 = new ItemProperty("Cat", "Name", "Different");

        // Assert
        Assert.Equal(prop1, prop2);
        Assert.NotEqual(prop1, prop3);
    }
}