using api.Data;
using api.Models;
using Microsoft.EntityFrameworkCore;

namespace api.Tests.Data;

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
    public void SeedDevelopmentData_AddsCategories_WhenDatabaseIsEmpty()
    {
        // Act
        DatabaseSeeder.SeedDevelopmentData(_context);

        // Assert
        Assert.Equal(7, _context.Categories.Count());
    }

    [Fact]
    public void SeedDevelopmentData_DoesNotAddCategories_WhenDatabaseHasData()
    {
        // Arrange
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
}

