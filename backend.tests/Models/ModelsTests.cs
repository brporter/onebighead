using backend.Models;

namespace backend.Tests.Models;

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
        Assert.Equal(0, item.TenantId);
        Assert.Equal(0, item.CollectionId);
        Assert.Null(item.CategoryId);
        Assert.Equal(string.Empty, item.Name);
        Assert.Equal(string.Empty, item.Summary);
        Assert.Equal(string.Empty, item.Description);
        Assert.NotNull(item.Properties);
        Assert.Empty(item.Properties);
        Assert.NotNull(item.Images);
        Assert.Empty(item.Images);
        Assert.Null(item.Tenant);
        Assert.Null(item.Collection);
        Assert.Null(item.Category);
    }

    [Fact]
    public void Item_Properties_CanBeSetAndGet()
    {
        // Arrange
        var tenant = new Tenant { Id = 1, Name = "Test Tenant" };
        var collection = new Collection { Id = 1, Name = "Test Collection", Slug = "test" };
        var category = new Category { Id = 1, Name = "Test Category" };
        var properties = new List<ItemProperty> { new("Cat", "Name", "Value") };
        var images = new List<ItemImage> { new("https://example.com/img.jpg", "Alt text") };

        // Act
        var item = new Item
        {
            Id = 1,
            TenantId = 1,
            CollectionId = 1,
            CategoryId = 1,
            Name = "Test Item",
            Summary = "Test Summary",
            Description = "Test Description",
            Properties = properties,
            Images = images,
            Tenant = tenant,
            Collection = collection,
            Category = category
        };

        // Assert
        Assert.Equal(1, item.Id);
        Assert.Equal(1, item.TenantId);
        Assert.Equal(1, item.CollectionId);
        Assert.Equal(1, item.CategoryId);
        Assert.Equal("Test Item", item.Name);
        Assert.Equal("Test Summary", item.Summary);
        Assert.Equal("Test Description", item.Description);
        Assert.Same(properties, item.Properties);
        Assert.Same(images, item.Images);
        Assert.Same(tenant, item.Tenant);
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
        Assert.Equal(0, collection.TenantId);
        Assert.Equal(string.Empty, collection.Name);
        Assert.Equal(string.Empty, collection.Description);
        Assert.Null(collection.HeroImageUrl);
        Assert.Equal(string.Empty, collection.Slug);
        Assert.NotNull(collection.Categories);
        Assert.Empty(collection.Categories);
        Assert.NotNull(collection.Items);
        Assert.Empty(collection.Items);
        Assert.Null(collection.Tenant);
    }

    [Fact]
    public void Collection_Properties_CanBeSetAndGet()
    {
        // Arrange
        var tenant = new Tenant { Id = 1, Name = "Test Tenant" };
        var categories = new List<Category> { new() { Name = "Cat1" } };
        var items = new List<Item> { new() { Name = "Item1" } };
        var createdAt = DateTime.UtcNow;

        // Act
        var collection = new Collection
        {
            Id = 1,
            TenantId = 1,
            Name = "Test Collection",
            Description = "Test Description",
            HeroImageUrl = "https://example.com/hero.jpg",
            Slug = "test-collection",
            CreatedAt = createdAt,
            Tenant = tenant,
            Categories = categories,
            Items = items
        };

        // Assert
        Assert.Equal(1, collection.Id);
        Assert.Equal(1, collection.TenantId);
        Assert.Equal("Test Collection", collection.Name);
        Assert.Equal("Test Description", collection.Description);
        Assert.Equal("https://example.com/hero.jpg", collection.HeroImageUrl);
        Assert.Equal("test-collection", collection.Slug);
        Assert.Equal(createdAt, collection.CreatedAt);
        Assert.Same(tenant, collection.Tenant);
        Assert.Same(categories, collection.Categories);
        Assert.Same(items, collection.Items);
    }
}

[Trait("Category", "Unit")]
public class TenantTests
{
    [Fact]
    public void Tenant_DefaultValues_AreCorrect()
    {
        // Act
        var tenant = new Tenant();

        // Assert
        Assert.Equal(0, tenant.Id);
        Assert.Equal(string.Empty, tenant.Name);
        Assert.NotNull(tenant.Users);
        Assert.Empty(tenant.Users);
        Assert.NotNull(tenant.Categories);
        Assert.Empty(tenant.Categories);
        Assert.NotNull(tenant.Collections);
        Assert.Empty(tenant.Collections);
    }

    [Fact]
    public void Tenant_Properties_CanBeSetAndGet()
    {
        // Arrange
        var users = new List<User> { new() { Email = "test@example.com" } };
        var categories = new List<Category> { new() { Name = "Cat1" } };
        var collections = new List<Collection> { new() { Name = "Col1", Slug = "col1" } };
        var createdAt = DateTime.UtcNow;

        // Act
        var tenant = new Tenant
        {
            Id = 1,
            Name = "Test Tenant",
            CreatedAt = createdAt,
            Users = users,
            Categories = categories,
            Collections = collections
        };

        // Assert
        Assert.Equal(1, tenant.Id);
        Assert.Equal("Test Tenant", tenant.Name);
        Assert.Equal(createdAt, tenant.CreatedAt);
        Assert.Same(users, tenant.Users);
        Assert.Same(categories, tenant.Categories);
        Assert.Same(collections, tenant.Collections);
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
        Assert.Equal(0, user.TenantId);
        Assert.Equal(string.Empty, user.Email);
        Assert.Equal(IdentityProvider.Microsoft, user.IdentityProvider);
        Assert.Equal(string.Empty, user.ProviderSubjectId);
        Assert.Null(user.Tenant);
    }

    [Fact]
    public void User_Properties_CanBeSetAndGet()
    {
        // Arrange
        var tenant = new Tenant { Id = 1, Name = "Test Tenant" };
        var createdAt = DateTime.UtcNow;

        // Act
        var user = new User
        {
            Id = 1,
            TenantId = 1,
            Email = "test@example.com",
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "google-sub-123",
            CreatedAt = createdAt,
            Tenant = tenant
        };

        // Assert
        Assert.Equal(1, user.Id);
        Assert.Equal(1, user.TenantId);
        Assert.Equal("test@example.com", user.Email);
        Assert.Equal(IdentityProvider.Google, user.IdentityProvider);
        Assert.Equal("google-sub-123", user.ProviderSubjectId);
        Assert.Equal(createdAt, user.CreatedAt);
        Assert.Same(tenant, user.Tenant);
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
