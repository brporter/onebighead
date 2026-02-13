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

[Trait("Category", "Unit")]
public class WorkspaceTests
{
    [Fact]
    public void Workspace_DefaultValues_AreCorrect()
    {
        // Act
        var workspace = new Workspace();

        // Assert
        Assert.Equal(0, workspace.Id);
        Assert.Equal(string.Empty, workspace.Name);
        Assert.NotNull(workspace.ActiveUsers);
        Assert.Empty(workspace.ActiveUsers);
        Assert.NotNull(workspace.WorkspaceUsers);
        Assert.Empty(workspace.WorkspaceUsers);
        Assert.NotNull(workspace.Categories);
        Assert.Empty(workspace.Categories);
        Assert.NotNull(workspace.Collections);
        Assert.Empty(workspace.Collections);
    }

    [Fact]
    public void Workspace_Properties_CanBeSetAndGet()
    {
        // Arrange
        var activeUsers = new List<User> { new() { Email = "test@example.com" } };
        var workspaceUsers = new List<WorkspaceUser> { new() { UserId = 1, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.Normal } };
        var categories = new List<Category> { new() { Name = "Cat1" } };
        var collections = new List<Collection> { new() { Name = "Col1", Slug = "col1" } };
        var createdAt = DateTime.UtcNow;

        // Act
        var workspace = new Workspace
        {
            Id = 1,
            Name = "Test Workspace",
            CreatedAt = createdAt,
            ActiveUsers = activeUsers,
            WorkspaceUsers = workspaceUsers,
            Categories = categories,
            Collections = collections
        };

        // Assert
        Assert.Equal(1, workspace.Id);
        Assert.Equal("Test Workspace", workspace.Name);
        Assert.Equal(createdAt, workspace.CreatedAt);
        Assert.Same(activeUsers, workspace.ActiveUsers);
        Assert.Same(workspaceUsers, workspace.WorkspaceUsers);
        Assert.Same(categories, workspace.Categories);
        Assert.Same(collections, workspace.Collections);
    }
}

[Trait("Category", "Unit")]
public class UserTests
{
    [Fact]
    public void User_DefaultValues_AreCorrect()
    {
        // Act
        var user = new User();

        // Assert
        Assert.Equal(0, user.Id);
        Assert.Equal(0, user.ActiveWorkspaceId);
        Assert.Equal(string.Empty, user.Email);
        Assert.Equal(IdentityProvider.None, user.IdentityProvider);
        Assert.Null(user.ProviderSubjectId);
        Assert.Null(user.ActiveWorkspace);
        Assert.False(user.IsLinked);
    }

    [Fact]
    public void User_IsLinked_ReturnsTrueWhenProviderSubjectIdIsSet()
    {
        // Arrange
        var user = new User
        {
            ProviderSubjectId = "provider-123"
        };

        // Assert
        Assert.True(user.IsLinked);
    }

    [Fact]
    public void User_IsLinked_ReturnsFalseWhenProviderSubjectIdIsNull()
    {
        // Arrange
        var user = new User
        {
            ProviderSubjectId = null
        };

        // Assert
        Assert.False(user.IsLinked);
    }

    [Fact]
    public void User_IsLinked_ReturnsFalseWhenProviderSubjectIdIsEmpty()
    {
        // Arrange
        var user = new User
        {
            ProviderSubjectId = string.Empty
        };

        // Assert
        Assert.False(user.IsLinked);
    }

    [Fact]
    public void User_Properties_CanBeSetAndGet()
    {
        // Arrange
        var workspace = new Workspace { Id = 1, Name = "Test Workspace" };
        var createdAt = DateTime.UtcNow;

        // Act
        var user = new User
        {
            Id = 1,
            ActiveWorkspaceId = 1,
            Email = "test@example.com",
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "google-sub-123",
            CreatedAt = createdAt,
            ActiveWorkspace = workspace
        };

        // Assert
        Assert.Equal(1, user.Id);
        Assert.Equal(1, user.ActiveWorkspaceId);
        Assert.Equal("test@example.com", user.Email);
        Assert.Equal(IdentityProvider.Google, user.IdentityProvider);
        Assert.Equal("google-sub-123", user.ProviderSubjectId);
        Assert.Equal(createdAt, user.CreatedAt);
        Assert.Same(workspace, user.ActiveWorkspace);
    }

    [Theory]
    [InlineData(IdentityProvider.Microsoft)]
    [InlineData(IdentityProvider.Google)]
    [InlineData(IdentityProvider.Apple)]
    public void User_IdentityProvider_AcceptsAllValues(IdentityProvider provider)
    {
        // Act
        var user = new User { IdentityProvider = provider };

        // Assert
        Assert.Equal(provider, user.IdentityProvider);
    }
}
