using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Models;

[Trait("Category", "Unit")]
public class CollectionTests
{
    [Fact]
    public void Collection_DefaultValues_AreCorrect()
    {
        // Act
        var collection = new Collection();

        // Assert
        Assert.Equal(0, collection.Id);
        Assert.Equal(0, collection.WorkspaceId);
        Assert.Equal(string.Empty, collection.Name);
        Assert.Equal(string.Empty, collection.Description);
        Assert.Null(collection.HeroImageUrl);
        Assert.Equal(string.Empty, collection.Slug);
        Assert.NotNull(collection.Categories);
        Assert.Empty(collection.Categories);
        Assert.NotNull(collection.Items);
        Assert.Empty(collection.Items);
        Assert.Null(collection.Workspace);
    }

    [Fact]
    public void Collection_Properties_CanBeSetAndGet()
    {
        // Arrange
        var workspace = new Workspace { Id = 1, Name = "Test Workspace" };
        var categories = new List<Category> { new() { Name = "Cat1" } };
        var items = new List<Item> { new() { Name = "Item1" } };
        var createdAt = DateTime.UtcNow;

        // Act
        var collection = new Collection
        {
            Id = 1,
            WorkspaceId = 1,
            Name = "Test Collection",
            Description = "Test Description",
            HeroImageUrl = "https://example.com/hero.jpg",
            Slug = "test-collection",
            CreatedAt = createdAt,
            Workspace = workspace,
            Categories = categories,
            Items = items
        };

        // Assert
        Assert.Equal(1, collection.Id);
        Assert.Equal(1, collection.WorkspaceId);
        Assert.Equal("Test Collection", collection.Name);
        Assert.Equal("Test Description", collection.Description);
        Assert.Equal("https://example.com/hero.jpg", collection.HeroImageUrl);
        Assert.Equal("test-collection", collection.Slug);
        Assert.Equal(createdAt, collection.CreatedAt);
        Assert.Same(workspace, collection.Workspace);
        Assert.Same(categories, collection.Categories);
        Assert.Same(items, collection.Items);
    }
}