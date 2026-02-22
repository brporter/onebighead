using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Tests.Integration.Data;

[Trait("Category", "Integration")]
public class ContentScanLogRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly ContentScanLogRepository _repository;

    public ContentScanLogRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _repository = new ContentScanLogRepository(_context);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    [Fact]
    public async Task CreateAsync_PersistsScanLog()
    {
        // Arrange
        var scanLog = new ContentScanLog
        {
            Id = Guid.NewGuid(),
            WorkspaceId = 1,
            UserId = 42,
            ScannerName = "TestScanner",
            IsMatch = true,
            MatchScore = 0.99,
            Details = "hash match",
            OriginalFileName = "test.jpg",
            ContentType = "image/jpeg",
            FileSizeBytes = 12345,
            ImageHash = "abc123",
            ScannedAt = DateTime.UtcNow,
            ReportSubmitted = false,
        };

        // Act
        var result = await _repository.CreateAsync(scanLog);

        // Assert
        Assert.Equal(scanLog.Id, result.Id);
        var persisted = await _context.ContentScanLogs.FindAsync(scanLog.Id);
        Assert.NotNull(persisted);
        Assert.Equal("TestScanner", persisted.ScannerName);
        Assert.True(persisted.IsMatch);
        Assert.Equal(0.99, persisted.MatchScore);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsExistingLog()
    {
        // Arrange
        var id = Guid.NewGuid();
        _context.ContentScanLogs.Add(new ContentScanLog
        {
            Id = id,
            WorkspaceId = 1,
            ScannerName = "TestScanner",
            IsMatch = false,
            MatchScore = 0.0,
            ContentType = "image/png",
            ScannedAt = DateTime.UtcNow,
        });
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(id);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(id, result.Id);
        Assert.Equal("TestScanner", result.ScannerName);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenNotFound()
    {
        // Act
        var result = await _repository.GetByIdAsync(Guid.NewGuid());

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task UpdateAsync_ModifiesExistingLog()
    {
        // Arrange
        var id = Guid.NewGuid();
        var scanLog = new ContentScanLog
        {
            Id = id,
            WorkspaceId = 1,
            ScannerName = "TestScanner",
            IsMatch = true,
            MatchScore = 0.95,
            ContentType = "image/jpeg",
            ScannedAt = DateTime.UtcNow,
            ReportSubmitted = false,
        };
        _context.ContentScanLogs.Add(scanLog);
        await _context.SaveChangesAsync();
        _context.ChangeTracker.Clear();

        // Act
        scanLog.ReportSubmitted = true;
        scanLog.ReportedAt = DateTime.UtcNow;
        await _repository.UpdateAsync(scanLog);

        // Assert
        _context.ChangeTracker.Clear();
        var updated = await _context.ContentScanLogs.FindAsync(id);
        Assert.NotNull(updated);
        Assert.True(updated.ReportSubmitted);
        Assert.NotNull(updated.ReportedAt);
    }

    [Fact]
    public async Task CreateAsync_SetsAllFields()
    {
        // Arrange
        var now = DateTime.UtcNow;
        var scanLog = new ContentScanLog
        {
            Id = Guid.NewGuid(),
            WorkspaceId = 5,
            UserId = 10,
            ScannerName = "PhotoDNA",
            IsMatch = true,
            MatchScore = 0.87,
            Details = "known hash",
            OriginalFileName = "suspicious.png",
            ContentType = "image/png",
            FileSizeBytes = 999999,
            ImageHash = "deadbeef",
            ScannedAt = now,
            ReportSubmitted = true,
            ReportedAt = now,
        };

        // Act
        await _repository.CreateAsync(scanLog);

        // Assert
        var persisted = await _context.ContentScanLogs.FindAsync(scanLog.Id);
        Assert.NotNull(persisted);
        Assert.Equal(5, persisted.WorkspaceId);
        Assert.Equal(10, persisted.UserId);
        Assert.Equal("PhotoDNA", persisted.ScannerName);
        Assert.True(persisted.IsMatch);
        Assert.Equal(0.87, persisted.MatchScore);
        Assert.Equal("known hash", persisted.Details);
        Assert.Equal("suspicious.png", persisted.OriginalFileName);
        Assert.Equal("image/png", persisted.ContentType);
        Assert.Equal(999999, persisted.FileSizeBytes);
        Assert.Equal("deadbeef", persisted.ImageHash);
        Assert.Equal(now, persisted.ScannedAt);
        Assert.True(persisted.ReportSubmitted);
        Assert.Equal(now, persisted.ReportedAt);
    }
}
