using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace backend.Tests.Integration.Data;

[Trait("Category", "Integration")]
public class UserRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly UserRepository _repository;

    public UserRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning))
            .Options;

        _context = new AppDbContext(options);
        _repository = new UserRepository(_context);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    private async Task<Tenant> CreateTestTenantAsync()
    {
        var tenant = new Tenant
        {
            Name = "test.example.com",
            CreatedAt = DateTime.UtcNow
        };
        _context.Tenants.Add(tenant);
        await _context.SaveChangesAsync();
        return tenant;
    }

    #region GetByEmailAsync Tests

    [Fact]
    public async Task GetByEmailAsync_ReturnsUser_WhenExists()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        var user = new User
        {
            TenantId = tenant.Id,
            Email = "test@example.com",
            IdentityProvider = IdentityProvider.Microsoft,
            ProviderSubjectId = "ms-123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByEmailAsync("test@example.com");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("test@example.com", result.Email);
        Assert.NotNull(result.Tenant);
    }

    [Fact]
    public async Task GetByEmailAsync_ReturnsNull_WhenNotExists()
    {
        // Act
        var result = await _repository.GetByEmailAsync("nonexistent@example.com");

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region GetByProviderIdAsync Tests

    [Fact]
    public async Task GetByProviderIdAsync_ReturnsUser_WhenExists()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        var user = new User
        {
            TenantId = tenant.Id,
            Email = "test@example.com",
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "google-sub-123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByProviderIdAsync(IdentityProvider.Google, "google-sub-123");

        // Assert
        Assert.NotNull(result);
        Assert.Equal(IdentityProvider.Google, result.IdentityProvider);
        Assert.Equal("google-sub-123", result.ProviderSubjectId);
    }

    [Fact]
    public async Task GetByProviderIdAsync_ReturnsNull_WhenProviderMismatch()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        var user = new User
        {
            TenantId = tenant.Id,
            Email = "test@example.com",
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "google-sub-123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Act - same subject ID but different provider
        var result = await _repository.GetByProviderIdAsync(IdentityProvider.Microsoft, "google-sub-123");

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region GetByIdAsync Tests

    [Fact]
    public async Task GetByIdAsync_ReturnsUser_WhenExists()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        var user = new User
        {
            TenantId = tenant.Id,
            Email = "test@example.com",
            IdentityProvider = IdentityProvider.Apple,
            ProviderSubjectId = "apple-123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(user.Id);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(user.Id, result.Id);
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

    #region CreateWithNewTenantAsync Tests

    [Fact]
    public async Task CreateWithNewTenantAsync_CreatesUserAndTenant()
    {
        // Act
        var result = await _repository.CreateWithNewTenantAsync(
            "newuser@example.com",
            IdentityProvider.Microsoft,
            "ms-new-user-123");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("newuser@example.com", result.Email);
        Assert.Equal(IdentityProvider.Microsoft, result.IdentityProvider);
        Assert.NotNull(result.Tenant);
        Assert.Equal("example.com", result.Tenant.Name);
    }

    [Fact]
    public async Task CreateWithNewTenantAsync_UsesDomainAsTenantName()
    {
        // Act
        var result = await _repository.CreateWithNewTenantAsync(
            "john@contoso.com",
            IdentityProvider.Google,
            "google-123");

        // Assert
        Assert.NotNull(result.Tenant);
        Assert.Equal("contoso.com", result.Tenant.Name);
    }

    [Fact]
    public async Task CreateWithNewTenantAsync_SavesUserToDatabase()
    {
        // Act
        var result = await _repository.CreateWithNewTenantAsync(
            "test@domain.com",
            IdentityProvider.Apple,
            "apple-456");

        // Assert
        var savedUser = await _context.Users.FindAsync(result.Id);
        Assert.NotNull(savedUser);
        Assert.Equal("test@domain.com", savedUser.Email);
    }

    [Fact]
    public async Task CreateWithNewTenantAsync_SavesTenantToDatabase()
    {
        // Act
        var result = await _repository.CreateWithNewTenantAsync(
            "user@newdomain.com",
            IdentityProvider.Microsoft,
            "ms-789");

        // Assert
        var savedTenant = await _context.Tenants.FindAsync(result.TenantId);
        Assert.NotNull(savedTenant);
        Assert.Equal("newdomain.com", savedTenant.Name);
    }

    [Fact]
    public async Task CreateWithNewTenantAsync_DoesNotCreateDefaultCollection()
    {
        // New behavior: collections are created through setup wizard, not auto-created
        // Act
        var result = await _repository.CreateWithNewTenantAsync(
            "user@test.com",
            IdentityProvider.Microsoft,
            "ms-collection-test");

        // Assert - no collections should be created
        var collections = await _context.Collections
            .Where(c => c.TenantId == result.TenantId)
            .ToListAsync();
        
        Assert.Empty(collections);
    }

    [Fact]
    public async Task CreateWithNewTenantAsync_DoesNotCreateUnassignedCategory()
    {
        // New behavior: unassigned category is created per collection during setup wizard
        // Act
        var result = await _repository.CreateWithNewTenantAsync(
            "user@category-test.com",
            IdentityProvider.Google,
            "google-category-test");

        // Assert - no categories should exist
        var categories = await _context.Categories
            .Where(c => c.TenantId == result.TenantId)
            .ToListAsync();
        Assert.Empty(categories);
    }

    [Fact]
    public async Task CreateWithNewTenantAsync_UsesWholeEmail_WhenNoAtSign()
    {
        // Act
        var result = await _repository.CreateWithNewTenantAsync(
            "localuser",
            IdentityProvider.Apple,
            "apple-local-test");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("localuser", result.Email);
        
        var tenant = await _context.Tenants.FindAsync(result.TenantId);
        Assert.NotNull(tenant);
        Assert.Equal("localuser", tenant.Name);
    }

    #endregion
}

