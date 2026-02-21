using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Models;

[Trait("Category", "Unit")]
public class ItemTests
{
    [Fact]
    public void Item_DefaultValues_AreCorrect()
    {
        // Act
        var item = new Item();

        // Assert
        Assert.Null(item.Id);
        Assert.Equal(0, item.WorkspaceId);
        Assert.Equal(0, item.CollectionId);
        Assert.Null(item.CategoryId);
        Assert.Equal(string.Empty, item.Name);
        Assert.Equal(string.Empty, item.Summary);
        Assert.Equal(string.Empty, item.Description);
        Assert.NotNull(item.Properties);
        Assert.Empty(item.Properties);
        Assert.NotNull(item.Images);
        Assert.Empty(item.Images);
        Assert.Null(item.Workspace);
        Assert.Null(item.Collection);
        Assert.Null(item.Category);
    }

    [Fact]
    public void Item_Properties_CanBeSetAndGet()
    {
        // Arrange
        var workspace = new Workspace { Id = 1, Name = "Test Workspace" };
        var collection = new Collection { Id = 1, Name = "Test Collection", Slug = "test" };
        var category = new Category { Id = 1, Name = "Test Category" };
        var properties = new List<ItemProperty> { new("Cat", "Name", "Value") };
        var images = new List<ItemImage> { new("https://example.com/img.jpg", "Alt text") };

        // Act
        var item = new Item
        {
            Id = 1,
            WorkspaceId = 1,
            CollectionId = 1,
            CategoryId = 1,
            Name = "Test Item",
            Summary = "Test Summary",
            Description = "Test Description",
            Properties = properties,
            Images = images,
            Workspace = workspace,
            Collection = collection,
            Category = category
        };

        // Assert
        Assert.Equal(1, item.Id);
        Assert.Equal(1, item.WorkspaceId);
        Assert.Equal(1, item.CollectionId);
        Assert.Equal(1, item.CategoryId);
        Assert.Equal("Test Item", item.Name);
        Assert.Equal("Test Summary", item.Summary);
        Assert.Equal("Test Description", item.Description);
        Assert.Same(properties, item.Properties);
        Assert.Same(images, item.Images);
        Assert.Same(workspace, item.Workspace);
        Assert.Same(collection, item.Collection);
        Assert.Same(category, item.Category);
    }
}