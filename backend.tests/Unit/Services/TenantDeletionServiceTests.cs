using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;

namespace OneBigHead.Server.Tests.Unit.Services;

public class TenantDeletionServiceTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly TenantDeletionService _service;
    private readonly Mock<ILogger<TenantDeletionService>> _loggerMock;

    public TenantDeletionServiceTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _loggerMock = new Mock<ILogger<TenantDeletionService>>();

        var tenantRepo = new TenantRepository(_context);
        var tenantUserRepo = new TenantUserRepository(_context);
        var userRepo = new UserRepository(_context);

        _service = new TenantDeletionService(
            _context, tenantRepo, tenantUserRepo, userRepo, _loggerMock.Object);
    }

    public void Dispose() => _context.Dispose();

    [Fact]
    public async Task SoftDeleteTenantAsync_SoftDeletesUser_WhenSingleTenantAdmin()
    {
        // Arrange: User is admin of exactly one tenant, no other memberships
        var tenant = new Tenant { Name = "Only Tenant", HasCompletedWelcome = true };
        _context.Tenants.Add(tenant);
        await _context.SaveChangesAsync();

        var user = new User
        {
            Email = "admin@test.com",
            ActiveTenantId = tenant.Id,
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "123"
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        var membership = new TenantUser
        {
            UserId = user.Id,
            TenantId = tenant.Id,
            TenantRole = TenantRole.TenantAdmin
        };
        _context.TenantUsers.Add(membership);
        await _context.SaveChangesAsync();

        // Act
        var result = await _service.SoftDeleteTenantAsync(tenant.Id, user.Id);

        // Assert
        Assert.True(result.Success);
        Assert.True(result.UserSoftDeleted);

        var deletedUser = await _context.Users.FindAsync(user.Id);
        Assert.True(deletedUser!.IsDeleted);
        Assert.NotNull(deletedUser.DeletedAt);
    }

    [Fact]
    public async Task SoftDeleteTenantAsync_DoesNotSoftDeleteUser_WhenUserHasOtherTenants()
    {
        // Arrange: User is admin of one tenant but member of another
        var tenant1 = new Tenant { Name = "Tenant 1", HasCompletedWelcome = true };
        var tenant2 = new Tenant { Name = "Tenant 2", HasCompletedWelcome = true };
        _context.Tenants.AddRange(tenant1, tenant2);
        await _context.SaveChangesAsync();

        var user = new User
        {
            Email = "admin@test.com",
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
        Assert.True(result.Success);
        Assert.False(result.UserSoftDeleted);
        Assert.Equal(tenant2.Id, result.NewActiveTenantId);

        var notDeletedUser = await _context.Users.FindAsync(user.Id);
        Assert.False(notDeletedUser!.IsDeleted);
    }
}
