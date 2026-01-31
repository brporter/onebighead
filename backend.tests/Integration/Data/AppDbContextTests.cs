using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Tests.Integration.Data;

[Trait("Category", "Integration")]
public class AppDbContextTests : IDisposable
{
    private readonly AppDbContext _context;

    public AppDbContextTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    [Fact]
    public void Categories_DbSet_IsNotNull()
    {
        // Assert
        Assert.NotNull(_context.Categories);
    }

    [Fact]
    public async Task CanAddAndRetrieveCategory()
    {
        // Arrange
        var category = new Category { Id = 1, TenantId = 1, Name = "Test", Description = "Test Desc" };

        // Act
        _context.Categories.Add(category);
        await _context.SaveChangesAsync();

        // Assert
        var result = await _context.Categories.FindAsync(1);
        Assert.NotNull(result);
        Assert.Equal("Test", result.Name);
    }

    [Fact]
    public async Task ParentChildRelationship_Works()
    {
        // Arrange
        var parent = new Category { Id = 1, TenantId = 1, Name = "Parent", Description = "Parent Desc" };
        var child = new Category { Id = 2, TenantId = 1, Name = "Child", Description = "Child Desc", ParentCategoryId = 1 };

        // Act
        _context.Categories.Add(parent);
        _context.Categories.Add(child);
        await _context.SaveChangesAsync();

        // Assert
        var childResult = await _context.Categories
            .Include(c => c.ParentCategory)
            .FirstOrDefaultAsync(c => c.Id == 2);
        
        Assert.NotNull(childResult);
        Assert.NotNull(childResult.ParentCategory);
        Assert.Equal("Parent", childResult.ParentCategory.Name);
    }

    [Fact]
    public async Task ChildCategories_NavigationProperty_Works()
    {
        // Arrange
        var parent = new Category { Id = 1, TenantId = 1, Name = "Parent", Description = "Parent Desc" };
        var child1 = new Category { Id = 2, TenantId = 1, Name = "Child 1", Description = "Child 1 Desc", ParentCategoryId = 1 };
        var child2 = new Category { Id = 3, TenantId = 1, Name = "Child 2", Description = "Child 2 Desc", ParentCategoryId = 1 };

        // Act
        _context.Categories.AddRange(parent, child1, child2);
        await _context.SaveChangesAsync();

        // Assert
        var parentResult = await _context.Categories
            .Include(c => c.ChildCategories)
            .FirstOrDefaultAsync(c => c.Id == 1);
        
        Assert.NotNull(parentResult);
        Assert.Equal(2, parentResult.ChildCategories.Count);
    }

    [Fact]
    public async Task DeleteParent_LeavesChildrenOrphanedWithRestrict()
    {
        // Arrange - Category self-referencing FK uses Restrict to avoid SQL Server cycles
        var parent = new Category { Id = 1, TenantId = 1, Name = "Parent", Description = "Parent Desc" };
        var child = new Category { Id = 2, TenantId = 1, Name = "Child", Description = "Child Desc", ParentCategoryId = 1 };

        _context.Categories.AddRange(parent, child);
        await _context.SaveChangesAsync();

        // Act - Must remove child reference first due to Restrict behavior
        child.ParentCategoryId = null;
        await _context.SaveChangesAsync();
        
        _context.Categories.Remove(parent);
        await _context.SaveChangesAsync();

        // Assert - Only child remains
        var categories = await _context.Categories.ToListAsync();
        Assert.Single(categories);
        Assert.Equal("Child", categories[0].Name);
    }
}

