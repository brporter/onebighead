using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using Microsoft.Extensions.Logging;
using Moq;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class TenantUserSoftDeleteIntegrationTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly TenantDeletionService _service;

    public TenantUserSoftDeleteIntegrationTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        var loggerMock = new Mock<ILogger<TenantDeletionService>>();

        var tenantRepo = new TenantRepository(_context);
        var tenantUserRepo = new TenantUserRepository(_context);
        var userRepo = new UserRepository(_context);

        _service = new TenantDeletionService(
            _context, tenantRepo, tenantUserRepo, userRepo, loggerMock.Object);
    }

    public void Dispose() => _context.Dispose();

    [Fact]
    public async Task FullFlow_SingleTenantAdminDeletesTenant_UserIsSoftDeleted()
    {
        // Arrange
        var tenant = new Tenant { Name = "Test", HasCompletedWelcome = true };
        _context.Tenants.Add(tenant);
        await _context.SaveChangesAsync();

        var user = new User
        {
            Email = "test@test.com",
            ActiveTenantId = tenant.Id,
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        _context.TenantUsers.Add(new TenantUser
        {
            UserId = user.Id,
            TenantId = tenant.Id,
            TenantRole = TenantRole.TenantAdmin
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _service.SoftDeleteTenantAsync(tenant.Id, user.Id);

        // Assert
        Assert.True(result.UserSoftDeleted);

        var deletedUser = await _context.Users.FindAsync(user.Id);
        Assert.True(deletedUser!.IsDeleted);
        Assert.NotNull(deletedUser.DeletedAt);

        var deletedTenant = await _context.Tenants.FindAsync(tenant.Id);
        Assert.True(deletedTenant!.IsDeleted);
    }

    [Fact]
    public async Task FullFlow_UserWithMultipleTenants_OnlyTenantDeleted()
    {
        // Arrange
        var tenant1 = new Tenant { Name = "Tenant 1", HasCompletedWelcome = true };
        var tenant2 = new Tenant { Name = "Tenant 2", HasCompletedWelcome = true };
        _context.Tenants.AddRange(tenant1, tenant2);
        await _context.SaveChangesAsync();

        var user = new User
        {
            Email = "test@test.com",
            ActiveTenantId = tenant1.Id,
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        _context.TenantUsers.AddRange(
            new TenantUser { UserId = user.Id, TenantId = tenant1.Id, TenantRole = TenantRole.TenantAdmin },
            new TenantUser { UserId = user.Id, TenantId = tenant2.Id, TenantRole = TenantRole.Normal }
        );
        await _context.SaveChangesAsync();

        // Act
        var result = await _service.SoftDeleteTenantAsync(tenant1.Id, user.Id);

        // Assert
        Assert.False(result.UserSoftDeleted);
        Assert.Equal(tenant2.Id, result.NewActiveTenantId);

        var notDeletedUser = await _context.Users.FindAsync(user.Id);
        Assert.False(notDeletedUser!.IsDeleted);
    }

    [Fact]
    public async Task FullFlow_NonAdminDeletesTenant_UserNotSoftDeleted()
    {
        // This test verifies that a normal member who somehow deletes a tenant
        // does NOT get soft-deleted (only TenantAdmin should be soft-deleted)

        // Arrange
        var tenant = new Tenant { Name = "Test", HasCompletedWelcome = true };
        _context.Tenants.Add(tenant);
        await _context.SaveChangesAsync();

        var user = new User
        {
            Email = "test@test.com",
            ActiveTenantId = tenant.Id,
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // User is Normal, not TenantAdmin
        _context.TenantUsers.Add(new TenantUser
        {
            UserId = user.Id,
            TenantId = tenant.Id,
            TenantRole = TenantRole.Normal
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _service.SoftDeleteTenantAsync(tenant.Id, user.Id);

        // Assert
        Assert.True(result.Success);
        Assert.False(result.UserSoftDeleted); // Not soft-deleted because not admin

        var notDeletedUser = await _context.Users.FindAsync(user.Id);
        Assert.False(notDeletedUser!.IsDeleted);
    }
}
