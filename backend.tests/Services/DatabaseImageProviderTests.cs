using OneBigHead.Server.Data;
using OneBigHead.Server.Services;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Tests.Services;

[Trait("Category", "Integration")]
public class DatabaseImageProviderTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly DatabaseImageProvider _provider;
    private const int TestTenantId = 1;
    private const int OtherTenantId = 2;

    public DatabaseImageProviderTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _provider = new DatabaseImageProvider(_context);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    #region StoreAsync Tests

    [Fact]
    public async Task StoreAsync_SavesImageToDatabase()
    {
        // Arrange
        var imageData = new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 };
        using var stream = new MemoryStream(imageData);

        // Act
        var result = await _provider.StoreAsync(TestTenantId, "test.jpg", "image/jpeg", stream);

        // Assert
        Assert.NotEqual(Guid.Empty, result.Key);
        Assert.Equal($"/api/images/{result.Key}", result.Url);

        var storedImage = await _context.StoredImages.FindAsync(result.Key);
        Assert.NotNull(storedImage);
        Assert.Equal(TestTenantId, storedImage.TenantId);
        Assert.Equal("test.jpg", storedImage.FileName);
        Assert.Equal("image/jpeg", storedImage.ContentType);
        Assert.Equal(imageData, storedImage.Data);
    }

    [Fact]
    public async Task StoreAsync_GeneratesUniqueKeys()
    {
        // Arrange
        var imageData = new byte[] { 0xFF, 0xD8, 0xFF };
        
        // Act
        using var stream1 = new MemoryStream(imageData);
        var result1 = await _provider.StoreAsync(TestTenantId, "test1.jpg", "image/jpeg", stream1);
        
        using var stream2 = new MemoryStream(imageData);
        var result2 = await _provider.StoreAsync(TestTenantId, "test2.jpg", "image/jpeg", stream2);

        // Assert
        Assert.NotEqual(result1.Key, result2.Key);
    }

    [Fact]
    public async Task StoreAsync_SetsCreatedAtTimestamp()
    {
        // Arrange
        var imageData = new byte[] { 0xFF, 0xD8, 0xFF };
        using var stream = new MemoryStream(imageData);
        var beforeStore = DateTime.UtcNow;

        // Act
        var result = await _provider.StoreAsync(TestTenantId, "test.jpg", "image/jpeg", stream);

        // Assert
        var storedImage = await _context.StoredImages.FindAsync(result.Key);
        Assert.NotNull(storedImage);
        Assert.True(storedImage.CreatedAt >= beforeStore);
        Assert.True(storedImage.CreatedAt <= DateTime.UtcNow);
    }

    #endregion

    #region RetrieveAsync Tests

    [Fact]
    public async Task RetrieveAsync_ReturnsImage_WhenExistsAndBelongsToTenant()
    {
        // Arrange
        var imageData = new byte[] { 0xFF, 0xD8, 0xFF };
        using var stream = new MemoryStream(imageData);
        var storeResult = await _provider.StoreAsync(TestTenantId, "test.jpg", "image/jpeg", stream);

        // Act
        var result = await _provider.RetrieveAsync(storeResult.Key, TestTenantId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(imageData, result.Data);
        Assert.Equal("image/jpeg", result.ContentType);
        Assert.Equal("test.jpg", result.FileName);
    }

    [Fact]
    public async Task RetrieveAsync_ReturnsNull_WhenImageDoesNotExist()
    {
        // Arrange
        var nonExistentKey = Guid.NewGuid();

        // Act
        var result = await _provider.RetrieveAsync(nonExistentKey, TestTenantId);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task RetrieveAsync_ReturnsNull_WhenImageBelongsToDifferentTenant()
    {
        // Arrange
        var imageData = new byte[] { 0xFF, 0xD8, 0xFF };
        using var stream = new MemoryStream(imageData);
        var storeResult = await _provider.StoreAsync(TestTenantId, "test.jpg", "image/jpeg", stream);

        // Act - Try to retrieve with different tenant ID
        var result = await _provider.RetrieveAsync(storeResult.Key, OtherTenantId);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task RetrieveAsync_EnforcesTenantIsolation()
    {
        // Arrange - Store images for two different tenants
        var imageData1 = new byte[] { 0xFF, 0xD8, 0xFF };
        var imageData2 = new byte[] { 0x89, 0x50, 0x4E, 0x47 };
        
        using var stream1 = new MemoryStream(imageData1);
        var result1 = await _provider.StoreAsync(TestTenantId, "tenant1.jpg", "image/jpeg", stream1);
        
        using var stream2 = new MemoryStream(imageData2);
        var result2 = await _provider.StoreAsync(OtherTenantId, "tenant2.png", "image/png", stream2);

        // Act & Assert - Each tenant can only access their own images
        var tenant1Image = await _provider.RetrieveAsync(result1.Key, TestTenantId);
        Assert.NotNull(tenant1Image);
        Assert.Equal(imageData1, tenant1Image.Data);

        var tenant2Image = await _provider.RetrieveAsync(result2.Key, OtherTenantId);
        Assert.NotNull(tenant2Image);
        Assert.Equal(imageData2, tenant2Image.Data);

        // Cross-tenant access should fail
        Assert.Null(await _provider.RetrieveAsync(result1.Key, OtherTenantId));
        Assert.Null(await _provider.RetrieveAsync(result2.Key, TestTenantId));
    }

    #endregion

    #region DeleteAsync Tests

    [Fact]
    public async Task DeleteAsync_RemovesImage_WhenExistsAndBelongsToTenant()
    {
        // Arrange
        var imageData = new byte[] { 0xFF, 0xD8, 0xFF };
        using var stream = new MemoryStream(imageData);
        var storeResult = await _provider.StoreAsync(TestTenantId, "test.jpg", "image/jpeg", stream);

        // Act
        await _provider.DeleteAsync(storeResult.Key, TestTenantId);

        // Assert
        var deletedImage = await _context.StoredImages.FindAsync(storeResult.Key);
        Assert.Null(deletedImage);
    }

    [Fact]
    public async Task DeleteAsync_DoesNotThrow_WhenImageDoesNotExist()
    {
        // Arrange
        var nonExistentKey = Guid.NewGuid();

        // Act & Assert - Should not throw
        await _provider.DeleteAsync(nonExistentKey, TestTenantId);
    }

    [Fact]
    public async Task DeleteAsync_DoesNotDelete_WhenImageBelongsToDifferentTenant()
    {
        // Arrange
        var imageData = new byte[] { 0xFF, 0xD8, 0xFF };
        using var stream = new MemoryStream(imageData);
        var storeResult = await _provider.StoreAsync(TestTenantId, "test.jpg", "image/jpeg", stream);

        // Act - Try to delete with different tenant ID
        await _provider.DeleteAsync(storeResult.Key, OtherTenantId);

        // Assert - Image should still exist
        var image = await _context.StoredImages.FindAsync(storeResult.Key);
        Assert.NotNull(image);
    }

    [Fact]
    public async Task DeleteAsync_EnforcesTenantIsolation()
    {
        // Arrange
        var imageData = new byte[] { 0xFF, 0xD8, 0xFF };
        using var stream = new MemoryStream(imageData);
        var storeResult = await _provider.StoreAsync(TestTenantId, "test.jpg", "image/jpeg", stream);

        // Act - Malicious tenant tries to delete another tenant's image
        await _provider.DeleteAsync(storeResult.Key, OtherTenantId);

        // Assert - Image should still exist (tenant isolation protected it)
        var retrievedImage = await _provider.RetrieveAsync(storeResult.Key, TestTenantId);
        Assert.NotNull(retrievedImage);
    }

    #endregion

    #region Integration Tests

    [Fact]
    public async Task FullLifecycle_StoreRetrieveDelete()
    {
        // Arrange
        var imageData = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
        using var stream = new MemoryStream(imageData);

        // Act - Store
        var storeResult = await _provider.StoreAsync(TestTenantId, "lifecycle.png", "image/png", stream);
        Assert.NotEqual(Guid.Empty, storeResult.Key);

        // Act - Retrieve
        var retrieved = await _provider.RetrieveAsync(storeResult.Key, TestTenantId);
        Assert.NotNull(retrieved);
        Assert.Equal(imageData, retrieved.Data);
        Assert.Equal("image/png", retrieved.ContentType);
        Assert.Equal("lifecycle.png", retrieved.FileName);

        // Act - Delete
        await _provider.DeleteAsync(storeResult.Key, TestTenantId);

        // Assert - Should be gone
        var afterDelete = await _provider.RetrieveAsync(storeResult.Key, TestTenantId);
        Assert.Null(afterDelete);
    }

    #endregion
}
