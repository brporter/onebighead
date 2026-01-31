using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Tests.Integration.Data;

[Trait("Category", "Integration")]
public class TenantRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly TenantRepository _repository;

    public TenantRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _repository = new TenantRepository(_context);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    private async Task<Tenant> CreateTestTenantAsync(string name = "Test Tenant", bool hasCompletedWelcome = false)
    {
        var tenant = new Tenant
        {
            Name = name,
            HasCompletedWelcome = hasCompletedWelcome,
            CreatedAt = DateTime.UtcNow
        };
        _context.Tenants.Add(tenant);
        await _context.SaveChangesAsync();
        return tenant;
    }

    #region GetByIdAsync Tests

    [Fact]
    public async Task GetByIdAsync_ReturnsTenant_WhenExists()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync("Test Tenant", false);

        // Act
        var result = await _repository.GetByIdAsync(tenant.Id);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Test Tenant", result.Name);
        Assert.False(result.HasCompletedWelcome);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenNotExists()
    {
        // Act
        var result = await _repository.GetByIdAsync(999);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region UpdateAsync Tests

    [Fact]
    public async Task UpdateAsync_SavesChanges()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync("Original Name", false);

        // Act
        tenant.Name = "Updated Name";
        tenant.HasCompletedWelcome = true;
        await _repository.UpdateAsync(tenant);

        // Assert - refetch to confirm changes were saved
        var updated = await _context.Tenants.FindAsync(tenant.Id);
        Assert.NotNull(updated);
        Assert.Equal("Updated Name", updated.Name);
        Assert.True(updated.HasCompletedWelcome);
    }

    [Fact]
    public async Task UpdateAsync_UpdatesHasCompletedWelcome()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync("Test", false);

        // Act
        tenant.HasCompletedWelcome = true;
        await _repository.UpdateAsync(tenant);

        // Assert
        var result = await _repository.GetByIdAsync(tenant.Id);
        Assert.NotNull(result);
        Assert.True(result.HasCompletedWelcome);
    }

    #endregion
}
