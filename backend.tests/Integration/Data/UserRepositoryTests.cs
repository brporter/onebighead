using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace OneBigHead.Server.Tests.Integration.Data;

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

    [Fact]
    public async Task CreateWithNewTenantAsync_SetsFirstUserAsTenantAdmin()
    {
        // Act
        var result = await _repository.CreateWithNewTenantAsync(
            "admin@newdomain.com",
            IdentityProvider.Microsoft,
            "ms-first-user");

        // Assert
        Assert.NotNull(result);
        Assert.Equal(TenantRole.TenantAdmin, result.TenantRole);
    }

    #endregion

    #region GetByTenantIdAsync Tests

    [Fact]
    public async Task GetByTenantIdAsync_ReturnsAllTenantUsers()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        _context.Users.AddRange(
            new User
            {
                TenantId = tenant.Id,
                Email = "user1@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "ms-user-1",
                TenantRole = TenantRole.TenantAdmin
            },
            new User
            {
                TenantId = tenant.Id,
                Email = "user2@example.com",
                IdentityProvider = IdentityProvider.Google,
                ProviderSubjectId = "google-user-2",
                TenantRole = TenantRole.Normal
            }
        );
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByTenantIdAsync(tenant.Id);

        // Assert
        var users = result.ToList();
        Assert.Equal(2, users.Count);
        Assert.Contains(users, u => u.Email == "user1@example.com");
        Assert.Contains(users, u => u.Email == "user2@example.com");
    }

    [Fact]
    public async Task GetByTenantIdAsync_ReturnsEmptyForNonExistentTenant()
    {
        // Act
        var result = await _repository.GetByTenantIdAsync(999);

        // Assert
        Assert.Empty(result);
    }

    #endregion

    #region CreatePendingUserAsync Tests

    [Fact]
    public async Task CreatePendingUserAsync_CreatesPendingUser()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();

        // Act
        var result = await _repository.CreatePendingUserAsync(tenant.Id, "pending@example.com", TenantRole.Normal);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("pending@example.com", result.Email);
        Assert.Equal(TenantRole.Normal, result.TenantRole);
        Assert.Equal(IdentityProvider.None, result.IdentityProvider);
        Assert.Null(result.ProviderSubjectId);
        Assert.False(result.IsLinked);
    }

    [Fact]
    public async Task CreatePendingUserAsync_CanCreateAsAdmin()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();

        // Act
        var result = await _repository.CreatePendingUserAsync(tenant.Id, "pendingadmin@example.com", TenantRole.TenantAdmin);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(TenantRole.TenantAdmin, result.TenantRole);
    }

    #endregion

    #region LinkUserAsync Tests

    [Fact]
    public async Task LinkUserAsync_LinksPendingUser()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        var pendingUser = await _repository.CreatePendingUserAsync(tenant.Id, "tolink@example.com", TenantRole.Normal);
        Assert.False(pendingUser.IsLinked);

        // Act
        var result = await _repository.LinkUserAsync(pendingUser.Id, IdentityProvider.Google, "google-linked-123");

        // Assert
        Assert.NotNull(result);
        Assert.Equal(IdentityProvider.Google, result.IdentityProvider);
        Assert.Equal("google-linked-123", result.ProviderSubjectId);
        Assert.True(result.IsLinked);
    }

    [Fact]
    public async Task LinkUserAsync_ReturnsNull_WhenUserNotFound()
    {
        // Act
        var result = await _repository.LinkUserAsync(999, IdentityProvider.Microsoft, "ms-999");

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region UpdateRoleAsync Tests

    [Fact]
    public async Task UpdateRoleAsync_UpdatesRole()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        var user = new User
        {
            TenantId = tenant.Id,
            Email = "rolechange@example.com",
            IdentityProvider = IdentityProvider.Microsoft,
            ProviderSubjectId = "ms-role-change",
            TenantRole = TenantRole.Normal
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.UpdateRoleAsync(user.Id, tenant.Id, TenantRole.TenantAdmin);

        // Assert
        Assert.True(result);
        var updatedUser = await _context.Users.FindAsync(user.Id);
        Assert.Equal(TenantRole.TenantAdmin, updatedUser!.TenantRole);
    }

    [Fact]
    public async Task UpdateRoleAsync_ReturnsFalse_WhenUserNotFound()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();

        // Act
        var result = await _repository.UpdateRoleAsync(999, tenant.Id, TenantRole.TenantAdmin);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task UpdateRoleAsync_ReturnsFalse_WhenWrongTenant()
    {
        // Arrange
        var tenant1 = await CreateTestTenantAsync();
        var tenant2 = new Tenant { Name = "other.com" };
        _context.Tenants.Add(tenant2);
        await _context.SaveChangesAsync();

        var user = new User
        {
            TenantId = tenant1.Id,
            Email = "wrongtenant@example.com",
            IdentityProvider = IdentityProvider.Microsoft,
            ProviderSubjectId = "ms-wrong-tenant",
            TenantRole = TenantRole.Normal
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Act - Try to update with wrong tenant ID
        var result = await _repository.UpdateRoleAsync(user.Id, tenant2.Id, TenantRole.TenantAdmin);

        // Assert
        Assert.False(result);
    }

    #endregion

    #region DeleteByIdAndTenantAsync Tests

    [Fact]
    public async Task DeleteByIdAndTenantAsync_DeletesUser()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        var user = new User
        {
            TenantId = tenant.Id,
            Email = "deleteme@example.com",
            IdentityProvider = IdentityProvider.Microsoft,
            ProviderSubjectId = "ms-delete-me"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        var userId = user.Id;

        // Act
        var result = await _repository.DeleteByIdAndTenantAsync(userId, tenant.Id);

        // Assert
        Assert.True(result);
        var deletedUser = await _context.Users.FindAsync(userId);
        Assert.Null(deletedUser);
    }

    [Fact]
    public async Task DeleteByIdAndTenantAsync_ReturnsFalse_WhenUserNotFound()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();

        // Act
        var result = await _repository.DeleteByIdAndTenantAsync(999, tenant.Id);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task DeleteByIdAndTenantAsync_ReturnsFalse_WhenWrongTenant()
    {
        // Arrange
        var tenant1 = await CreateTestTenantAsync();
        var tenant2 = new Tenant { Name = "other2.com" };
        _context.Tenants.Add(tenant2);
        await _context.SaveChangesAsync();

        var user = new User
        {
            TenantId = tenant1.Id,
            Email = "cantdelete@example.com",
            IdentityProvider = IdentityProvider.Microsoft,
            ProviderSubjectId = "ms-cant-delete"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Act - Try to delete with wrong tenant ID
        var result = await _repository.DeleteByIdAndTenantAsync(user.Id, tenant2.Id);

        // Assert
        Assert.False(result);
        // Verify user still exists
        var stillExists = await _context.Users.FindAsync(user.Id);
        Assert.NotNull(stillExists);
    }

    #endregion

    #region CountAdminsInTenantAsync Tests

    [Fact]
    public async Task CountAdminsInTenantAsync_CountsAdmins()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        _context.Users.AddRange(
            new User
            {
                TenantId = tenant.Id,
                Email = "admin1@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "ms-admin-1",
                TenantRole = TenantRole.TenantAdmin
            },
            new User
            {
                TenantId = tenant.Id,
                Email = "admin2@example.com",
                IdentityProvider = IdentityProvider.Google,
                ProviderSubjectId = "google-admin-2",
                TenantRole = TenantRole.TenantAdmin
            },
            new User
            {
                TenantId = tenant.Id,
                Email = "normal@example.com",
                IdentityProvider = IdentityProvider.Apple,
                ProviderSubjectId = "apple-normal",
                TenantRole = TenantRole.Normal
            }
        );
        await _context.SaveChangesAsync();

        // Act
        var count = await _repository.CountAdminsInTenantAsync(tenant.Id);

        // Assert
        Assert.Equal(2, count);
    }

    [Fact]
    public async Task CountAdminsInTenantAsync_ReturnsZero_WhenNoAdmins()
    {
        // Arrange
        var tenant = await CreateTestTenantAsync();
        _context.Users.Add(new User
        {
            TenantId = tenant.Id,
            Email = "onlynormal@example.com",
            IdentityProvider = IdentityProvider.Microsoft,
            ProviderSubjectId = "ms-only-normal",
            TenantRole = TenantRole.Normal
        });
        await _context.SaveChangesAsync();

        // Act
        var count = await _repository.CountAdminsInTenantAsync(tenant.Id);

        // Assert
        Assert.Equal(0, count);
    }

    [Fact]
    public async Task CountAdminsInTenantAsync_ReturnsZero_ForNonExistentTenant()
    {
        // Act
        var count = await _repository.CountAdminsInTenantAsync(999);

        // Assert
        Assert.Equal(0, count);
    }

    #endregion
}

