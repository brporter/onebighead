using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Tests.Data;

public class DatabaseSeederTests : IDisposable
{
    private readonly AppDbContext _context;

    public DatabaseSeederTests()
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
    public void SeedDevelopmentData_AddsTenantAndCategories_WhenDatabaseIsEmpty()
    {
        // Act
        DatabaseSeeder.SeedDevelopmentData(_context);

        // Assert
        Assert.Equal(1, _context.Tenants.Count());
        Assert.Equal(8, _context.Categories.Count()); // 7 regular + 1 system category
    }

    [Fact]
    public void SeedDevelopmentData_DoesNotAddCategories_WhenDatabaseHasData()
    {
        // Arrange - Add tenant first, then category
        var tenant = new Tenant { Id = 1, Name = "test.local" };
        _context.Tenants.Add(tenant);
        _context.SaveChanges();
        
        _context.Categories.Add(new Category { Id = 100, TenantId = 1, Name = "Existing", Description = "Existing Desc" });
        _context.SaveChanges();

        // Act
        DatabaseSeeder.SeedDevelopmentData(_context);

        // Assert
        Assert.Equal(1, _context.Categories.Count());
        Assert.Equal("Existing", _context.Categories.First().Name);
    }

    [Fact]
    public void SeedDevelopmentData_CreatesCorrectHierarchy()
    {
        // Act
        DatabaseSeeder.SeedDevelopmentData(_context);

        // Assert
        var motorola = _context.Categories.FirstOrDefault(c => c.Name == "Motorola 68000 Computers");
        var compactMac = _context.Categories.FirstOrDefault(c => c.Name == "Compact Macintosh");
        var appleII = _context.Categories.FirstOrDefault(c => c.Name == "Apple II");

        Assert.NotNull(motorola);
        Assert.NotNull(compactMac);
        Assert.NotNull(appleII);
        Assert.Null(motorola.ParentCategoryId);
        Assert.Equal(motorola.Id, compactMac.ParentCategoryId);
        Assert.Equal(motorola.Id, appleII.ParentCategoryId);
    }

    [Fact]
    public void SeedDevelopmentData_SetsCorrectTenantId()
    {
        // Act
        DatabaseSeeder.SeedDevelopmentData(_context);

        // Assert
        Assert.All(_context.Categories, c => Assert.Equal(1, c.TenantId));
    }

    [Fact]
    public void SeedDevelopmentData_CreatesDefaultTenant()
    {
        // Act
        DatabaseSeeder.SeedDevelopmentData(_context);

        // Assert
        var tenant = _context.Tenants.FirstOrDefault();
        Assert.NotNull(tenant);
        Assert.Equal("development.local", tenant.Name);
    }

    [Fact]
    public void SeedDevelopmentData_CreatesUnassignedItemsSystemCategory()
    {
        // Act
        DatabaseSeeder.SeedDevelopmentData(_context);

        // Assert
        var unassignedCategory = _context.Categories.FirstOrDefault(c => c.Name == "Unassigned Items");
        Assert.NotNull(unassignedCategory);
        Assert.True(unassignedCategory.IsSystem);
        Assert.Equal(1, unassignedCategory.TenantId);
        Assert.Null(unassignedCategory.ParentCategoryId);
    }
}

