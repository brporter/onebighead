using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Tests.Data;

[Trait("Category", "Integration")]
public class CategoryRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly CategoryRepository _repository;
    private const int TestTenantId = 1;
    private const int OtherTenantId = 2;
    private const int TestCollectionId = 1;
    private const int OtherCollectionId = 2;

    public CategoryRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _repository = new CategoryRepository(_context);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    #region GetAllAsync Tests

    [Fact]
    public async Task GetAllAsync_ReturnsOnlyCategoriesForTenant()
    {
        // Arrange
        var categories = new List<Category>
        {
            new() { Id = 1, TenantId = TestTenantId, Name = "Category 1", Description = "Desc 1" },
            new() { Id = 2, TenantId = TestTenantId, Name = "Category 2", Description = "Desc 2" },
            new() { Id = 3, TenantId = OtherTenantId, Name = "Category 3", Description = "Desc 3" }
        };
        await _context.Categories.AddRangeAsync(categories);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetAllAsync(TestTenantId);

        // Assert
        Assert.Equal(2, result.Count());
        Assert.All(result, c => Assert.Equal(TestTenantId, c.TenantId));
    }

    [Fact]
    public async Task GetAllAsync_ReturnsEmptyList_WhenNoCategories()
    {
        // Act
        var result = await _repository.GetAllAsync(TestTenantId);

        // Assert
        Assert.Empty(result);
    }

    #endregion

    #region GetByCollectionAsync Tests

    [Fact]
    public async Task GetByCollectionAsync_ReturnsOnlyCategoriesForCollection()
    {
        // Arrange
        var categories = new List<Category>
        {
            new() { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Category 1", Description = "Desc 1" },
            new() { Id = 2, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Category 2", Description = "Desc 2" },
            new() { Id = 3, TenantId = TestTenantId, CollectionId = OtherCollectionId, Name = "Category 3", Description = "Desc 3" }
        };
        await _context.Categories.AddRangeAsync(categories);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByCollectionAsync(TestCollectionId, TestTenantId);

        // Assert
        Assert.Equal(2, result.Count());
        Assert.All(result, c => Assert.Equal(TestCollectionId, c.CollectionId));
    }

    [Fact]
    public async Task GetByCollectionAsync_FiltersOutOtherTenants()
    {
        // Arrange
        var categories = new List<Category>
        {
            new() { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Category 1", Description = "Desc 1" },
            new() { Id = 2, TenantId = OtherTenantId, CollectionId = TestCollectionId, Name = "Category 2", Description = "Desc 2" }
        };
        await _context.Categories.AddRangeAsync(categories);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByCollectionAsync(TestCollectionId, TestTenantId);

        // Assert
        Assert.Single(result);
        Assert.Equal(TestTenantId, result.First().TenantId);
    }

    [Fact]
    public async Task GetByCollectionAsync_ReturnsEmptyList_WhenNoCategories()
    {
        // Act
        var result = await _repository.GetByCollectionAsync(TestCollectionId, TestTenantId);

        // Assert
        Assert.Empty(result);
    }

    #endregion

    #region GetByIdAsync Tests

    [Fact]
    public async Task GetByIdAsync_ReturnsCategory_WhenExistsForTenant()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = TestTenantId, Name = "Test Category", Description = "Test Desc" };
        await _context.Categories.AddAsync(category);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(1, TestTenantId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Test Category", result.Name);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenNotExists()
    {
        // Act
        var result = await _repository.GetByIdAsync(999, TestTenantId);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenExistsButDifferentTenant()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = OtherTenantId, Name = "Test Category", Description = "Test Desc" };
        await _context.Categories.AddAsync(category);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(1, TestTenantId);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region CreateAsync Tests

    [Fact]
    public async Task CreateAsync_AddsCategory_AndReturnsIt()
    {
        // Arrange
        var category = new Category { TenantId = TestTenantId, Name = "New Category", Description = "New Desc" };

        // Act
        var result = await _repository.CreateAsync(category);

        // Assert
        Assert.NotNull(result);
        Assert.True(result.Id > 0);
        Assert.Equal("New Category", result.Name);

        // Verify it was saved
        var savedCategory = await _context.Categories.FindAsync(result.Id);
        Assert.NotNull(savedCategory);
    }

    [Fact]
    public async Task CreateAsync_WithParentCategory_SetsRelationship()
    {
        // Arrange
        var parentCategory = new Category { Id = 1, TenantId = TestTenantId, Name = "Parent", Description = "Parent Desc" };
        await _context.Categories.AddAsync(parentCategory);
        await _context.SaveChangesAsync();

        var childCategory = new Category { TenantId = TestTenantId, Name = "Child", Description = "Child Desc", ParentCategoryId = 1 };

        // Act
        var result = await _repository.CreateAsync(childCategory);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(1, result.ParentCategoryId);
    }

    #endregion

    #region UpdateAsync Tests

    [Fact]
    public async Task UpdateAsync_UpdatesCategory_WhenExistsForTenant()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = TestTenantId, Name = "Original", Description = "Original Desc" };
        await _context.Categories.AddAsync(category);
        await _context.SaveChangesAsync();
        _context.Entry(category).State = EntityState.Detached;

        var updatedCategory = new Category { Name = "Updated", Description = "Updated Desc", ParentCategoryId = null };

        // Act
        var result = await _repository.UpdateAsync(1, updatedCategory, TestTenantId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Updated", result.Name);
        Assert.Equal("Updated Desc", result.Description);
        Assert.Equal(TestTenantId, result.TenantId); // TenantId should not change
    }

    [Fact]
    public async Task UpdateAsync_ReturnsNull_WhenNotExists()
    {
        // Arrange
        var updatedCategory = new Category { Name = "Updated", Description = "Updated Desc" };

        // Act
        var result = await _repository.UpdateAsync(999, updatedCategory, TestTenantId);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task UpdateAsync_ReturnsNull_WhenExistsButDifferentTenant()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = OtherTenantId, Name = "Original", Description = "Original Desc" };
        await _context.Categories.AddAsync(category);
        await _context.SaveChangesAsync();
        _context.Entry(category).State = EntityState.Detached;

        var updatedCategory = new Category { Name = "Updated", Description = "Updated Desc" };

        // Act
        var result = await _repository.UpdateAsync(1, updatedCategory, TestTenantId);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region DeleteAsync Tests

    [Fact]
    public async Task DeleteAsync_RemovesCategory_AndReturnsTrue()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = TestTenantId, Name = "To Delete", Description = "Delete Desc" };
        await _context.Categories.AddAsync(category);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.DeleteAsync(1, TestTenantId);

        // Assert
        Assert.True(result);
        var deletedCategory = await _context.Categories.FindAsync(1);
        Assert.Null(deletedCategory);
    }

    [Fact]
    public async Task DeleteAsync_ReturnsFalse_WhenNotExists()
    {
        // Act
        var result = await _repository.DeleteAsync(999, TestTenantId);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task DeleteAsync_ReturnsFalse_WhenExistsButDifferentTenant()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = OtherTenantId, Name = "To Delete", Description = "Delete Desc" };
        await _context.Categories.AddAsync(category);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.DeleteAsync(1, TestTenantId);

        // Assert
        Assert.False(result);
        // Verify the category still exists
        var existingCategory = await _context.Categories.FindAsync(1);
        Assert.NotNull(existingCategory);
    }

    #endregion

    #region GetSystemCategoryAsync Tests

    [Fact]
    public async Task GetSystemCategoryAsync_ReturnsSystemCategory_WhenExists()
    {
        // Arrange
        var systemCategory = new Category 
        { 
            Id = 1, 
            TenantId = TestTenantId, 
            CollectionId = TestCollectionId,
            Name = "Unassigned Items", 
            Description = "Items without a category", 
            IsSystem = true 
        };
        await _context.Categories.AddAsync(systemCategory);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetSystemCategoryAsync(TestCollectionId, TestTenantId, "Unassigned Items");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Unassigned Items", result.Name);
        Assert.True(result.IsSystem);
    }

    [Fact]
    public async Task GetSystemCategoryAsync_ReturnsNull_WhenNotExists()
    {
        // Act
        var result = await _repository.GetSystemCategoryAsync(TestCollectionId, TestTenantId, "Unassigned Items");

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetSystemCategoryAsync_ReturnsNull_WhenCategoryIsNotSystem()
    {
        // Arrange
        var nonSystemCategory = new Category 
        { 
            Id = 1, 
            TenantId = TestTenantId, 
            CollectionId = TestCollectionId,
            Name = "Unassigned Items", 
            Description = "Not a system category", 
            IsSystem = false 
        };
        await _context.Categories.AddAsync(nonSystemCategory);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetSystemCategoryAsync(TestCollectionId, TestTenantId, "Unassigned Items");

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetSystemCategoryAsync_ReturnsNull_WhenDifferentTenant()
    {
        // Arrange
        var systemCategory = new Category 
        { 
            Id = 1, 
            TenantId = OtherTenantId, 
            CollectionId = OtherCollectionId,
            Name = "Unassigned Items", 
            Description = "Items without a category", 
            IsSystem = true 
        };
        await _context.Categories.AddAsync(systemCategory);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetSystemCategoryAsync(TestCollectionId, TestTenantId, "Unassigned Items");

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region DeleteAsync System Category Tests

    [Fact]
    public async Task DeleteAsync_ReturnsFalse_WhenCategoryIsSystem()
    {
        // Arrange
        var systemCategory = new Category 
        { 
            Id = 1, 
            TenantId = TestTenantId, 
            Name = "Unassigned Items", 
            Description = "System category", 
            IsSystem = true 
        };
        await _context.Categories.AddAsync(systemCategory);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.DeleteAsync(1, TestTenantId);

        // Assert
        Assert.False(result);
        // Verify the category still exists
        var existingCategory = await _context.Categories.FindAsync(1);
        Assert.NotNull(existingCategory);
    }

    [Fact]
    public async Task DeleteAsync_MovesSubcategoriesToParent()
    {
        // Arrange
        var parentCategory = new Category { Id = 1, TenantId = TestTenantId, Name = "Parent", Description = "Parent Desc" };
        var categoryToDelete = new Category { Id = 2, TenantId = TestTenantId, Name = "To Delete", Description = "Delete Desc", ParentCategoryId = 1 };
        var subcategory = new Category { Id = 3, TenantId = TestTenantId, Name = "Subcategory", Description = "Sub Desc", ParentCategoryId = 2 };
        
        await _context.Categories.AddRangeAsync(parentCategory, categoryToDelete, subcategory);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.DeleteAsync(2, TestTenantId);

        // Assert
        Assert.True(result);
        var updatedSubcategory = await _context.Categories.FindAsync(3);
        Assert.NotNull(updatedSubcategory);
        Assert.Equal(1, updatedSubcategory.ParentCategoryId); // Should now point to parent
    }

    [Fact]
    public async Task DeleteAsync_MovesSubcategoriesToRoot_WhenNoParent()
    {
        // Arrange
        var categoryToDelete = new Category { Id = 1, TenantId = TestTenantId, Name = "To Delete", Description = "Delete Desc", ParentCategoryId = null };
        var subcategory = new Category { Id = 2, TenantId = TestTenantId, Name = "Subcategory", Description = "Sub Desc", ParentCategoryId = 1 };
        
        await _context.Categories.AddRangeAsync(categoryToDelete, subcategory);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.DeleteAsync(1, TestTenantId);

        // Assert
        Assert.True(result);
        var updatedSubcategory = await _context.Categories.FindAsync(2);
        Assert.NotNull(updatedSubcategory);
        Assert.Null(updatedSubcategory.ParentCategoryId); // Should now be root
    }

    [Fact]
    public async Task DeleteAsync_MovesItemsToUnassignedCategory()
    {
        // Arrange
        var unassignedCategory = new Category 
        { 
            Id = 1, 
            TenantId = TestTenantId, 
            Name = "Unassigned Items", 
            Description = "System category", 
            IsSystem = true 
        };
        var categoryToDelete = new Category { Id = 2, TenantId = TestTenantId, Name = "To Delete", Description = "Delete Desc" };
        var item = new Item 
        { 
            Id = 1, 
            TenantId = TestTenantId, 
            CategoryId = 2, 
            Name = "Test Item", 
            Summary = "Summary", 
            Description = "Description" 
        };
        
        await _context.Categories.AddRangeAsync(unassignedCategory, categoryToDelete);
        await _context.Items.AddAsync(item);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.DeleteAsync(2, TestTenantId);

        // Assert
        Assert.True(result);
        var updatedItem = await _context.Items.FindAsync(1);
        Assert.NotNull(updatedItem);
        Assert.Equal(1, updatedItem.CategoryId); // Should now be in Unassigned Items
    }

    [Fact]
    public async Task DeleteAsync_MovesMultipleItemsToUnassignedCategory()
    {
        // Arrange
        var unassignedCategory = new Category 
        { 
            Id = 1, 
            TenantId = TestTenantId, 
            Name = "Unassigned Items", 
            Description = "System category", 
            IsSystem = true 
        };
        var categoryToDelete = new Category { Id = 2, TenantId = TestTenantId, Name = "To Delete", Description = "Delete Desc" };
        var items = new List<Item>
        {
            new() { Id = 1, TenantId = TestTenantId, CategoryId = 2, Name = "Item 1", Summary = "Sum1", Description = "Desc1" },
            new() { Id = 2, TenantId = TestTenantId, CategoryId = 2, Name = "Item 2", Summary = "Sum2", Description = "Desc2" },
            new() { Id = 3, TenantId = TestTenantId, CategoryId = 2, Name = "Item 3", Summary = "Sum3", Description = "Desc3" }
        };
        
        await _context.Categories.AddRangeAsync(unassignedCategory, categoryToDelete);
        await _context.Items.AddRangeAsync(items);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.DeleteAsync(2, TestTenantId);

        // Assert
        Assert.True(result);
        var updatedItems = await _context.Items.Where(i => i.TenantId == TestTenantId).ToListAsync();
        Assert.All(updatedItems, item => Assert.Equal(1, item.CategoryId));
    }

    [Fact]
    public async Task DeleteAsync_SetsItemCategoryToNull_WhenNoUnassignedCategory()
    {
        // Arrange - no Unassigned Items category exists
        var categoryToDelete = new Category { Id = 1, TenantId = TestTenantId, Name = "To Delete", Description = "Delete Desc" };
        var item = new Item 
        { 
            Id = 1, 
            TenantId = TestTenantId, 
            CategoryId = 1, 
            Name = "Test Item", 
            Summary = "Summary", 
            Description = "Description" 
        };
        
        await _context.Categories.AddAsync(categoryToDelete);
        await _context.Items.AddAsync(item);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.DeleteAsync(1, TestTenantId);

        // Assert
        Assert.True(result);
        var updatedItem = await _context.Items.FindAsync(1);
        Assert.NotNull(updatedItem);
        Assert.Null(updatedItem.CategoryId); // Should be null when no Unassigned Items category
    }

    #endregion

    #region Template Association Tests

    [Fact]
    public async Task GetTemplateIdsAsync_ReturnsTemplateIds_WhenAssociationsExist()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Category 1", Description = "Desc" };
        var template1 = new ItemTemplate { Id = 1, TenantId = TestTenantId, Name = "Template 1", Description = "Desc" };
        var template2 = new ItemTemplate { Id = 2, TenantId = TestTenantId, Name = "Template 2", Description = "Desc" };
        
        await _context.Categories.AddAsync(category);
        await _context.ItemTemplates.AddRangeAsync(template1, template2);
        await _context.CategoryItemTemplates.AddRangeAsync(
            new CategoryItemTemplate { CategoryId = 1, ItemTemplateId = 1, SortOrder = 0 },
            new CategoryItemTemplate { CategoryId = 1, ItemTemplateId = 2, SortOrder = 1 }
        );
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetTemplateIdsAsync(1, TestTenantId);

        // Assert
        Assert.Equal(2, result.Count);
        Assert.Equal(new List<int> { 1, 2 }, result);
    }

    [Fact]
    public async Task GetTemplateIdsAsync_ReturnsEmpty_WhenNoAssociations()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Category 1", Description = "Desc" };
        await _context.Categories.AddAsync(category);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetTemplateIdsAsync(1, TestTenantId);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public async Task GetTemplateIdsAsync_ReturnsEmpty_WhenCategoryNotFound()
    {
        // Act
        var result = await _repository.GetTemplateIdsAsync(999, TestTenantId);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public async Task GetTemplateIdsAsync_RespectsOrder()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Category 1", Description = "Desc" };
        var template1 = new ItemTemplate { Id = 1, TenantId = TestTenantId, Name = "Template 1", Description = "Desc" };
        var template2 = new ItemTemplate { Id = 2, TenantId = TestTenantId, Name = "Template 2", Description = "Desc" };
        var template3 = new ItemTemplate { Id = 3, TenantId = TestTenantId, Name = "Template 3", Description = "Desc" };
        
        await _context.Categories.AddAsync(category);
        await _context.ItemTemplates.AddRangeAsync(template1, template2, template3);
        await _context.CategoryItemTemplates.AddRangeAsync(
            new CategoryItemTemplate { CategoryId = 1, ItemTemplateId = 3, SortOrder = 0 },
            new CategoryItemTemplate { CategoryId = 1, ItemTemplateId = 1, SortOrder = 1 },
            new CategoryItemTemplate { CategoryId = 1, ItemTemplateId = 2, SortOrder = 2 }
        );
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetTemplateIdsAsync(1, TestTenantId);

        // Assert
        Assert.Equal(new List<int> { 3, 1, 2 }, result);
    }

    [Fact]
    public async Task SetTemplateIdsAsync_CreatesAssociations()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Category 1", Description = "Desc" };
        var template1 = new ItemTemplate { Id = 1, TenantId = TestTenantId, Name = "Template 1", Description = "Desc" };
        var template2 = new ItemTemplate { Id = 2, TenantId = TestTenantId, Name = "Template 2", Description = "Desc" };
        
        await _context.Categories.AddAsync(category);
        await _context.ItemTemplates.AddRangeAsync(template1, template2);
        await _context.SaveChangesAsync();

        // Act
        await _repository.SetTemplateIdsAsync(1, new List<int> { 1, 2 }, TestTenantId);

        // Assert
        var associations = await _context.CategoryItemTemplates.Where(ct => ct.CategoryId == 1).ToListAsync();
        Assert.Equal(2, associations.Count);
    }

    [Fact]
    public async Task SetTemplateIdsAsync_ReplacesExistingAssociations()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Category 1", Description = "Desc" };
        var template1 = new ItemTemplate { Id = 1, TenantId = TestTenantId, Name = "Template 1", Description = "Desc" };
        var template2 = new ItemTemplate { Id = 2, TenantId = TestTenantId, Name = "Template 2", Description = "Desc" };
        var template3 = new ItemTemplate { Id = 3, TenantId = TestTenantId, Name = "Template 3", Description = "Desc" };
        
        await _context.Categories.AddAsync(category);
        await _context.ItemTemplates.AddRangeAsync(template1, template2, template3);
        await _context.CategoryItemTemplates.AddAsync(new CategoryItemTemplate { CategoryId = 1, ItemTemplateId = 1, SortOrder = 0 });
        await _context.SaveChangesAsync();

        // Act
        await _repository.SetTemplateIdsAsync(1, new List<int> { 2, 3 }, TestTenantId);

        // Assert
        var associations = await _context.CategoryItemTemplates.Where(ct => ct.CategoryId == 1).ToListAsync();
        Assert.Equal(2, associations.Count);
        Assert.DoesNotContain(associations, a => a.ItemTemplateId == 1);
        Assert.Contains(associations, a => a.ItemTemplateId == 2);
        Assert.Contains(associations, a => a.ItemTemplateId == 3);
    }

    [Fact]
    public async Task SetTemplateIdsAsync_DoesNothing_WhenCategoryNotFound()
    {
        // Act
        await _repository.SetTemplateIdsAsync(999, new List<int> { 1 }, TestTenantId);

        // Assert
        var associations = await _context.CategoryItemTemplates.ToListAsync();
        Assert.Empty(associations);
    }

    [Fact]
    public async Task GetInheritedTemplateIdsAsync_ReturnsOwnTemplates()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Category 1", Description = "Desc" };
        var template = new ItemTemplate { Id = 1, TenantId = TestTenantId, Name = "Template 1", Description = "Desc" };
        
        await _context.Categories.AddAsync(category);
        await _context.ItemTemplates.AddAsync(template);
        await _context.CategoryItemTemplates.AddAsync(new CategoryItemTemplate { CategoryId = 1, ItemTemplateId = 1, SortOrder = 0 });
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetInheritedTemplateIdsAsync(1, TestTenantId);

        // Assert
        Assert.Single(result);
        Assert.Contains(1, result);
    }

    [Fact]
    public async Task GetInheritedTemplateIdsAsync_InheritsFromParent()
    {
        // Arrange
        var parentCategory = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Parent", Description = "Desc" };
        var childCategory = new Category { Id = 2, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Child", Description = "Desc", ParentCategoryId = 1 };
        var template = new ItemTemplate { Id = 1, TenantId = TestTenantId, Name = "Template 1", Description = "Desc" };
        
        await _context.Categories.AddRangeAsync(parentCategory, childCategory);
        await _context.ItemTemplates.AddAsync(template);
        await _context.CategoryItemTemplates.AddAsync(new CategoryItemTemplate { CategoryId = 1, ItemTemplateId = 1, SortOrder = 0 });
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetInheritedTemplateIdsAsync(2, TestTenantId);

        // Assert
        Assert.Single(result);
        Assert.Contains(1, result);
    }

    [Fact]
    public async Task GetInheritedTemplateIdsAsync_CombinesChildAndParentTemplates()
    {
        // Arrange
        var parentCategory = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Parent", Description = "Desc" };
        var childCategory = new Category { Id = 2, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Child", Description = "Desc", ParentCategoryId = 1 };
        var template1 = new ItemTemplate { Id = 1, TenantId = TestTenantId, Name = "Template 1", Description = "Desc" };
        var template2 = new ItemTemplate { Id = 2, TenantId = TestTenantId, Name = "Template 2", Description = "Desc" };
        
        await _context.Categories.AddRangeAsync(parentCategory, childCategory);
        await _context.ItemTemplates.AddRangeAsync(template1, template2);
        await _context.CategoryItemTemplates.AddRangeAsync(
            new CategoryItemTemplate { CategoryId = 1, ItemTemplateId = 1, SortOrder = 0 },
            new CategoryItemTemplate { CategoryId = 2, ItemTemplateId = 2, SortOrder = 0 }
        );
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetInheritedTemplateIdsAsync(2, TestTenantId);

        // Assert
        Assert.Equal(2, result.Count);
        Assert.Contains(1, result);
        Assert.Contains(2, result);
    }

    [Fact]
    public async Task GetInheritedTemplateIdsAsync_ChildTemplatesTakePrecedence()
    {
        // Arrange - same template on parent and child should only appear once
        var parentCategory = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Parent", Description = "Desc" };
        var childCategory = new Category { Id = 2, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Child", Description = "Desc", ParentCategoryId = 1 };
        var template = new ItemTemplate { Id = 1, TenantId = TestTenantId, Name = "Template 1", Description = "Desc" };
        
        await _context.Categories.AddRangeAsync(parentCategory, childCategory);
        await _context.ItemTemplates.AddAsync(template);
        await _context.CategoryItemTemplates.AddRangeAsync(
            new CategoryItemTemplate { CategoryId = 1, ItemTemplateId = 1, SortOrder = 0 },
            new CategoryItemTemplate { CategoryId = 2, ItemTemplateId = 1, SortOrder = 0 }
        );
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetInheritedTemplateIdsAsync(2, TestTenantId);

        // Assert
        Assert.Single(result); // No duplicates
        Assert.Contains(1, result);
    }

    [Fact]
    public async Task GetInheritedTemplateIdsAsync_InheritsMultipleLevels()
    {
        // Arrange - grandparent -> parent -> child
        var grandparent = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Grandparent", Description = "Desc" };
        var parent = new Category { Id = 2, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Parent", Description = "Desc", ParentCategoryId = 1 };
        var child = new Category { Id = 3, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Child", Description = "Desc", ParentCategoryId = 2 };
        var template1 = new ItemTemplate { Id = 1, TenantId = TestTenantId, Name = "Template 1", Description = "Desc" };
        var template2 = new ItemTemplate { Id = 2, TenantId = TestTenantId, Name = "Template 2", Description = "Desc" };
        var template3 = new ItemTemplate { Id = 3, TenantId = TestTenantId, Name = "Template 3", Description = "Desc" };
        
        await _context.Categories.AddRangeAsync(grandparent, parent, child);
        await _context.ItemTemplates.AddRangeAsync(template1, template2, template3);
        await _context.CategoryItemTemplates.AddRangeAsync(
            new CategoryItemTemplate { CategoryId = 1, ItemTemplateId = 1, SortOrder = 0 },
            new CategoryItemTemplate { CategoryId = 2, ItemTemplateId = 2, SortOrder = 0 },
            new CategoryItemTemplate { CategoryId = 3, ItemTemplateId = 3, SortOrder = 0 }
        );
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetInheritedTemplateIdsAsync(3, TestTenantId);

        // Assert
        Assert.Equal(3, result.Count);
        Assert.Contains(1, result);
        Assert.Contains(2, result);
        Assert.Contains(3, result);
    }

    [Fact]
    public async Task GetTemplateIdsByCategoryAsync_ReturnsAllMappings()
    {
        // Arrange
        var category1 = new Category { Id = 1, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Category 1", Description = "Desc" };
        var category2 = new Category { Id = 2, TenantId = TestTenantId, CollectionId = TestCollectionId, Name = "Category 2", Description = "Desc" };
        var template1 = new ItemTemplate { Id = 1, TenantId = TestTenantId, Name = "Template 1", Description = "Desc" };
        var template2 = new ItemTemplate { Id = 2, TenantId = TestTenantId, Name = "Template 2", Description = "Desc" };
        
        await _context.Categories.AddRangeAsync(category1, category2);
        await _context.ItemTemplates.AddRangeAsync(template1, template2);
        await _context.CategoryItemTemplates.AddRangeAsync(
            new CategoryItemTemplate { CategoryId = 1, ItemTemplateId = 1, SortOrder = 0 },
            new CategoryItemTemplate { CategoryId = 1, ItemTemplateId = 2, SortOrder = 1 },
            new CategoryItemTemplate { CategoryId = 2, ItemTemplateId = 2, SortOrder = 0 }
        );
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetTemplateIdsByCategoryAsync(TestCollectionId, TestTenantId);

        // Assert
        Assert.Equal(2, result.Count);
        Assert.Equal(new List<int> { 1, 2 }, result[1]);
        Assert.Equal(new List<int> { 2 }, result[2]);
    }

    #endregion
}

