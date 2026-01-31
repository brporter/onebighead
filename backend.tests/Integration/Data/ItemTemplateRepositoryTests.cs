using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Tests.Integration.Data;

[Trait("Category", "Integration")]
public class ItemTemplateRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly ItemTemplateRepository _repository;
    private const int TestTenantId = 1;
    private const int OtherTenantId = 2;
    private const int TestCollectionId = 1;

    public ItemTemplateRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _repository = new ItemTemplateRepository(_context);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    #region GetAllAccessibleAsync Tests

    [Fact]
    public async Task GetAllAccessibleAsync_ReturnsTenantAndSystemTemplates()
    {
        // Arrange
        var templates = new List<ItemTemplate>
        {
            new() { Id = 1, TenantId = TestTenantId, Name = "Tenant Template", Description = "Desc" },
            new() { Id = 2, TenantId = null, Name = "System Template", Description = "Desc" },
            new() { Id = 3, TenantId = OtherTenantId, Name = "Other Tenant", Description = "Desc" }
        };
        await _context.ItemTemplates.AddRangeAsync(templates);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetAllAccessibleAsync(TestTenantId);

        // Assert
        Assert.Equal(2, result.Count());
        Assert.Contains(result, t => t.Name == "Tenant Template");
        Assert.Contains(result, t => t.Name == "System Template");
    }

    [Fact]
    public async Task GetAllAccessibleAsync_ExcludesOverriddenSystemTemplates()
    {
        // Arrange - tenant has a template with same name as system template
        var templates = new List<ItemTemplate>
        {
            new() { Id = 1, TenantId = TestTenantId, Name = "Common Name", Description = "Tenant version" },
            new() { Id = 2, TenantId = null, Name = "Common Name", Description = "System version" },
            new() { Id = 3, TenantId = null, Name = "Unique System", Description = "Desc" }
        };
        await _context.ItemTemplates.AddRangeAsync(templates);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetAllAccessibleAsync(TestTenantId);

        // Assert
        Assert.Equal(2, result.Count());
        Assert.Contains(result, t => t.Name == "Common Name" && t.TenantId == TestTenantId);
        Assert.Contains(result, t => t.Name == "Unique System");
        Assert.DoesNotContain(result, t => t.Name == "Common Name" && t.TenantId == null);
    }

    #endregion

    #region GetSystemTemplatesAsync Tests

    [Fact]
    public async Task GetSystemTemplatesAsync_ReturnsOnlySystemTemplates()
    {
        // Arrange
        var templates = new List<ItemTemplate>
        {
            new() { Id = 1, TenantId = TestTenantId, Name = "Tenant Template", Description = "Desc" },
            new() { Id = 2, TenantId = null, Name = "System Template", Description = "Desc" }
        };
        await _context.ItemTemplates.AddRangeAsync(templates);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetSystemTemplatesAsync(TestTenantId);

        // Assert
        Assert.Single(result);
        Assert.Equal("System Template", result.First().Name);
    }

    #endregion

    #region GetTenantTemplatesAsync Tests

    [Fact]
    public async Task GetTenantTemplatesAsync_ReturnsOnlyTenantTemplates()
    {
        // Arrange
        var templates = new List<ItemTemplate>
        {
            new() { Id = 1, TenantId = TestTenantId, Name = "Tenant Template", Description = "Desc" },
            new() { Id = 2, TenantId = null, Name = "System Template", Description = "Desc" },
            new() { Id = 3, TenantId = OtherTenantId, Name = "Other Template", Description = "Desc" }
        };
        await _context.ItemTemplates.AddRangeAsync(templates);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetTenantTemplatesAsync(TestTenantId);

        // Assert
        Assert.Single(result);
        Assert.Equal("Tenant Template", result.First().Name);
    }

    #endregion

    #region GetByIdAsync Tests

    [Fact]
    public async Task GetByIdAsync_ReturnsTenantTemplate()
    {
        // Arrange
        var template = new ItemTemplate { Id = 1, TenantId = TestTenantId, Name = "Test", Description = "Desc" };
        await _context.ItemTemplates.AddAsync(template);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(1, TestTenantId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Test", result.Name);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsSystemTemplate()
    {
        // Arrange
        var template = new ItemTemplate { Id = 1, TenantId = null, Name = "System", Description = "Desc" };
        await _context.ItemTemplates.AddAsync(template);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(1, TestTenantId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("System", result.Name);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenOtherTenant()
    {
        // Arrange
        var template = new ItemTemplate { Id = 1, TenantId = OtherTenantId, Name = "Other", Description = "Desc" };
        await _context.ItemTemplates.AddAsync(template);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(1, TestTenantId);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region CreateAsync Tests

    [Fact]
    public async Task CreateAsync_AddsTemplateToDatabase()
    {
        // Arrange
        var template = new ItemTemplate
        {
            TenantId = TestTenantId,
            Name = "New Template",
            Description = "Description"
        };

        // Act
        var result = await _repository.CreateAsync(template);

        // Assert
        Assert.True(result.Id > 0);
        Assert.NotEqual(default, result.CreatedAt);
        Assert.NotEqual(default, result.UpdatedAt);
    }

    #endregion

    #region UpdateAsync Tests

    [Fact]
    public async Task UpdateAsync_UpdatesTenantTemplate()
    {
        // Arrange
        var template = new ItemTemplate
        {
            Id = 1,
            TenantId = TestTenantId,
            Name = "Original",
            Description = "Original Desc",
            CreatedAt = DateTime.UtcNow.AddDays(-1)
        };
        await _context.ItemTemplates.AddAsync(template);
        await _context.SaveChangesAsync();
        _context.Entry(template).State = EntityState.Detached;

        var updates = new ItemTemplate
        {
            Name = "Updated",
            Description = "Updated Desc"
        };

        // Act
        var result = await _repository.UpdateAsync(1, updates, TestTenantId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Updated", result.Name);
        Assert.Equal("Updated Desc", result.Description);
    }

    [Fact]
    public async Task UpdateAsync_ReturnsNull_ForSystemTemplate()
    {
        // Arrange
        var template = new ItemTemplate { Id = 1, TenantId = null, Name = "System", Description = "Desc" };
        await _context.ItemTemplates.AddAsync(template);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.UpdateAsync(1, new ItemTemplate { Name = "Updated" }, TestTenantId);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region DeleteAsync Tests

    [Fact]
    public async Task DeleteAsync_DeletesTenantTemplate()
    {
        // Arrange
        var template = new ItemTemplate { Id = 1, TenantId = TestTenantId, Name = "Test", Description = "Desc" };
        await _context.ItemTemplates.AddAsync(template);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.DeleteAsync(1, TestTenantId);

        // Assert
        Assert.True(result);
        Assert.Null(await _context.ItemTemplates.FindAsync(1));
    }

    [Fact]
    public async Task DeleteAsync_ReturnsFalse_ForSystemTemplate()
    {
        // Arrange
        var template = new ItemTemplate { Id = 1, TenantId = null, Name = "System", Description = "Desc" };
        await _context.ItemTemplates.AddAsync(template);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.DeleteAsync(1, TestTenantId);

        // Assert
        Assert.False(result);
        Assert.NotNull(await _context.ItemTemplates.FindAsync(1));
    }

    #endregion

    #region Collection Association Tests

    [Fact]
    public async Task AssociateWithCollectionAsync_CreatesAssociation()
    {
        // Arrange
        var template = new ItemTemplate { Id = 1, TenantId = TestTenantId, Name = "Test", Description = "Desc" };
        var collection = new Collection { Id = TestCollectionId, TenantId = TestTenantId, Name = "Test Collection", Slug = "test" };
        await _context.ItemTemplates.AddAsync(template);
        await _context.Collections.AddAsync(collection);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.AssociateWithCollectionAsync(1, TestCollectionId);

        // Assert
        Assert.True(result);
        Assert.True(await _context.CollectionItemTemplates.AnyAsync(ct => 
            ct.CollectionId == TestCollectionId && ct.ItemTemplateId == 1));
    }

    [Fact]
    public async Task AssociateWithCollectionAsync_ReturnsTrue_WhenAlreadyAssociated()
    {
        // Arrange
        var template = new ItemTemplate { Id = 1, TenantId = TestTenantId, Name = "Test", Description = "Desc" };
        var collection = new Collection { Id = TestCollectionId, TenantId = TestTenantId, Name = "Test Collection", Slug = "test" };
        await _context.ItemTemplates.AddAsync(template);
        await _context.Collections.AddAsync(collection);
        await _context.CollectionItemTemplates.AddAsync(new CollectionItemTemplate
        {
            CollectionId = TestCollectionId,
            ItemTemplateId = 1
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.AssociateWithCollectionAsync(1, TestCollectionId);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task DisassociateFromCollectionAsync_RemovesAssociation()
    {
        // Arrange
        await _context.CollectionItemTemplates.AddAsync(new CollectionItemTemplate
        {
            CollectionId = TestCollectionId,
            ItemTemplateId = 1
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.DisassociateFromCollectionAsync(1, TestCollectionId);

        // Assert
        Assert.True(result);
        Assert.False(await _context.CollectionItemTemplates.AnyAsync(ct => 
            ct.CollectionId == TestCollectionId && ct.ItemTemplateId == 1));
    }

    [Fact]
    public async Task DisassociateFromCollectionAsync_ReturnsFalse_WhenNotAssociated()
    {
        // Act
        var result = await _repository.DisassociateFromCollectionAsync(1, TestCollectionId);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task AssociateMultipleWithCollectionAsync_CreatesBatchAssociations()
    {
        // Arrange
        var collection = new Collection { Id = TestCollectionId, TenantId = TestTenantId, Name = "Test", Slug = "test" };
        await _context.Collections.AddAsync(collection);
        await _context.SaveChangesAsync();

        // Act
        await _repository.AssociateMultipleWithCollectionAsync(new[] { 1, 2, 3 }, TestCollectionId);

        // Assert
        var associations = await _context.CollectionItemTemplates
            .Where(ct => ct.CollectionId == TestCollectionId)
            .ToListAsync();
        Assert.Equal(3, associations.Count);
    }

    [Fact]
    public async Task AssociateMultipleWithCollectionAsync_SkipsExisting()
    {
        // Arrange
        var collection = new Collection { Id = TestCollectionId, TenantId = TestTenantId, Name = "Test", Slug = "test" };
        await _context.Collections.AddAsync(collection);
        await _context.CollectionItemTemplates.AddAsync(new CollectionItemTemplate
        {
            CollectionId = TestCollectionId,
            ItemTemplateId = 1
        });
        await _context.SaveChangesAsync();

        // Act
        await _repository.AssociateMultipleWithCollectionAsync(new[] { 1, 2, 3 }, TestCollectionId);

        // Assert
        var associations = await _context.CollectionItemTemplates
            .Where(ct => ct.CollectionId == TestCollectionId)
            .ToListAsync();
        Assert.Equal(3, associations.Count);
    }

    #endregion

    #region GetByCollectionAsync Tests

    [Fact]
    public async Task GetByCollectionAsync_ReturnsAssociatedTemplates()
    {
        // Arrange
        var templates = new List<ItemTemplate>
        {
            new() { Id = 1, TenantId = TestTenantId, Name = "Template 1", Description = "Desc" },
            new() { Id = 2, TenantId = TestTenantId, Name = "Template 2", Description = "Desc" },
            new() { Id = 3, TenantId = TestTenantId, Name = "Template 3", Description = "Desc" }
        };
        var collection = new Collection { Id = TestCollectionId, TenantId = TestTenantId, Name = "Test", Slug = "test" };
        var associations = new List<CollectionItemTemplate>
        {
            new() { CollectionId = TestCollectionId, ItemTemplateId = 1 },
            new() { CollectionId = TestCollectionId, ItemTemplateId = 2 }
        };

        await _context.ItemTemplates.AddRangeAsync(templates);
        await _context.Collections.AddAsync(collection);
        await _context.CollectionItemTemplates.AddRangeAsync(associations);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByCollectionAsync(TestCollectionId);

        // Assert
        Assert.Equal(2, result.Count());
        Assert.Contains(result, t => t.Name == "Template 1");
        Assert.Contains(result, t => t.Name == "Template 2");
        Assert.DoesNotContain(result, t => t.Name == "Template 3");
    }

    #endregion

    #region CopySystemTemplateAsync Tests

    [Fact]
    public async Task CopySystemTemplateAsync_CreatesNewTenantTemplate()
    {
        // Arrange
        var systemTemplate = new ItemTemplate
        {
            Id = 1,
            TenantId = null,
            Name = "System Template",
            Description = "Original Description",
            Properties = new List<ItemTemplateProperty>
            {
                new() { Id = 1, ItemTemplateId = 1, Category = "Cat1", Name = "Prop1", SortOrder = 0 }
            }
        };
        await _context.ItemTemplates.AddAsync(systemTemplate);
        await _context.SaveChangesAsync();

        var updates = new ItemTemplate
        {
            Name = "My Copy",
            Description = "Custom Description",
            Properties = new List<ItemTemplateProperty>
            {
                new() { Category = "Cat1", Name = "Prop1", SortOrder = 0 },
                new() { Category = "Cat2", Name = "Prop2", SortOrder = 1 }
            }
        };

        // Act
        var result = await _repository.CopySystemTemplateAsync(1, TestTenantId, updates);

        // Assert
        Assert.NotEqual(1, result.Id);
        Assert.Equal(TestTenantId, result.TenantId);
        Assert.Equal("My Copy", result.Name);
        Assert.Equal("Custom Description", result.Description);
        Assert.Equal(2, result.Properties.Count);
    }

    [Fact]
    public async Task CopySystemTemplateAsync_ThrowsWhenSystemTemplateNotFound()
    {
        // Arrange
        var updates = new ItemTemplate { Name = "Test" };

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _repository.CopySystemTemplateAsync(999, TestTenantId, updates));
    }

    #endregion
}
