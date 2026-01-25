using backend.Utilities;

namespace backend.Tests.Utilities;

public class ETagHelperTests
{
    private class TestItem
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
    }

    [Fact]
    public void ComputeETag_Collection_ReturnsSameValueForSameData()
    {
        // Arrange
        var items1 = new List<TestItem>
        {
            new() { Id = 1, Name = "Item 1" },
            new() { Id = 2, Name = "Item 2" }
        };
        var items2 = new List<TestItem>
        {
            new() { Id = 1, Name = "Item 1" },
            new() { Id = 2, Name = "Item 2" }
        };

        // Act
        var etag1 = ETagHelper.ComputeETag(items1, i => i.Id);
        var etag2 = ETagHelper.ComputeETag(items2, i => i.Id);

        // Assert
        Assert.Equal(etag1, etag2);
    }

    [Fact]
    public void ComputeETag_Collection_ReturnsDifferentValueForDifferentData()
    {
        // Arrange
        var items1 = new List<TestItem>
        {
            new() { Id = 1, Name = "Item 1" }
        };
        var items2 = new List<TestItem>
        {
            new() { Id = 1, Name = "Item 1 Modified" }
        };

        // Act
        var etag1 = ETagHelper.ComputeETag(items1, i => i.Id);
        var etag2 = ETagHelper.ComputeETag(items2, i => i.Id);

        // Assert
        Assert.NotEqual(etag1, etag2);
    }

    [Fact]
    public void ComputeETag_Collection_OrdersItemsBeforeHashing()
    {
        // Arrange - same items but in different order
        var items1 = new List<TestItem>
        {
            new() { Id = 1, Name = "Item 1" },
            new() { Id = 2, Name = "Item 2" }
        };
        var items2 = new List<TestItem>
        {
            new() { Id = 2, Name = "Item 2" },
            new() { Id = 1, Name = "Item 1" }
        };

        // Act
        var etag1 = ETagHelper.ComputeETag(items1, i => i.Id);
        var etag2 = ETagHelper.ComputeETag(items2, i => i.Id);

        // Assert - same ETag because items are ordered by Id before hashing
        Assert.Equal(etag1, etag2);
    }

    [Fact]
    public void ComputeETag_Collection_ReturnsQuotedString()
    {
        // Arrange
        var items = new List<TestItem>
        {
            new() { Id = 1, Name = "Item 1" }
        };

        // Act
        var etag = ETagHelper.ComputeETag(items, i => i.Id);

        // Assert
        Assert.StartsWith("\"", etag);
        Assert.EndsWith("\"", etag);
    }

    [Fact]
    public void ComputeETag_Collection_EmptyList_ReturnsValidETag()
    {
        // Arrange
        var items = new List<TestItem>();

        // Act
        var etag = ETagHelper.ComputeETag(items, i => i.Id);

        // Assert
        Assert.NotNull(etag);
        Assert.StartsWith("\"", etag);
        Assert.EndsWith("\"", etag);
    }

    [Fact]
    public void ComputeETag_SingleObject_ReturnsSameValueForSameData()
    {
        // Arrange
        var item1 = new TestItem { Id = 1, Name = "Item 1" };
        var item2 = new TestItem { Id = 1, Name = "Item 1" };

        // Act
        var etag1 = ETagHelper.ComputeETag(item1);
        var etag2 = ETagHelper.ComputeETag(item2);

        // Assert
        Assert.Equal(etag1, etag2);
    }

    [Fact]
    public void ComputeETag_SingleObject_ReturnsDifferentValueForDifferentData()
    {
        // Arrange
        var item1 = new TestItem { Id = 1, Name = "Item 1" };
        var item2 = new TestItem { Id = 1, Name = "Item 1 Modified" };

        // Act
        var etag1 = ETagHelper.ComputeETag(item1);
        var etag2 = ETagHelper.ComputeETag(item2);

        // Assert
        Assert.NotEqual(etag1, etag2);
    }

    [Fact]
    public void ComputeETag_SingleObject_ReturnsQuotedString()
    {
        // Arrange
        var item = new TestItem { Id = 1, Name = "Item 1" };

        // Act
        var etag = ETagHelper.ComputeETag(item);

        // Assert
        Assert.StartsWith("\"", etag);
        Assert.EndsWith("\"", etag);
    }
}
