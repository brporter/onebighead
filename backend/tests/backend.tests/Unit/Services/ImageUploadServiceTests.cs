using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using OneBigHead.Server.Services.Images;

namespace OneBigHead.Server.Tests.Unit.Services;

public class ImageUploadServiceTests
{
    private static readonly byte[] Original = [1, 2, 3];
    private readonly Mock<IImageFormatDetector> _formats = new();
    private readonly Mock<IContentScanner> _scanner = new();
    private readonly Mock<IContentScanLogRepository> _logs = new();
    private readonly Mock<ICsamReportingService> _reporting = new();
    private readonly Mock<IImageProcessor> _processor = new();
    private readonly Mock<IImageProvider> _images = new();
    private ImageUploadService Service => new(_formats.Object, _scanner.Object, _logs.Object, _reporting.Object,
        _processor.Object, _images.Object, new Clock(), NullLogger<ImageUploadService>.Instance);

    public ImageUploadServiceTests()
    {
        _formats.Setup(formats => formats.Detect(Original)).Returns("image/png");
        _scanner.Setup(scanner => scanner.ScanAsync(Original, "image/png", default)).ReturnsAsync(new ContentScanResult(false, 0, "Test"));
        _processor.Setup(processor => processor.ResizeIfNeeded(Original, "image/png")).Returns((Original, "image/png"));
    }

    [Fact]
    public async Task Upload_ScansOriginalBytesBeforeProcessingAndOwnsTheStorageStream()
    {
        var sequence = new MockSequence();
        byte[] processed = [9, 8];
        var stored = new StoredImageInfo(Guid.NewGuid(), "/api/images/test");
        Stream? storageStream = null;
        _scanner.InSequence(sequence).Setup(scanner => scanner.ScanAsync(Original, "image/png", default))
            .ReturnsAsync(new ContentScanResult(false, 0, "Test"));
        _processor.InSequence(sequence).Setup(processor => processor.ResizeIfNeeded(Original, "image/png")).Returns((processed, "image/jpeg"));
        _images.InSequence(sequence).Setup(images => images.StoreAsync(7, "photo.png", "image/jpeg", It.IsAny<Stream>()))
            .Callback<int, string, string, Stream>((_, _, _, stream) =>
            {
                storageStream = stream;
                using var copy = new MemoryStream();
                stream.CopyTo(copy);
                Assert.Equal(processed, copy.ToArray());
            }).ReturnsAsync(stored);

        var result = await Service.UploadAsync(7, 42, "photo.png", Original);

        Assert.Same(stored, result.Image);
        Assert.Null(result.Error);
        Assert.False(storageStream!.CanRead);
        Assert.Equal(new byte[] { 1, 2, 3 }, Original);
        _scanner.Verify(scanner => scanner.ScanAsync(Original, "image/png", default), Times.Once);
        _logs.VerifyNoOtherCalls();
        _reporting.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(null)]
    [InlineData(42)]
    public async Task Rejection_PersistsTheOriginalAuditBeforeReportingWithoutProcessing(int? userId)
    {
        _scanner.Setup(scanner => scanner.ScanAsync(Original, "image/png", default)).ReturnsAsync(new ContentScanResult(true, .9, "Test", "Match"));
        ContentScanLog? captured = null;
        _logs.Setup(logs => logs.CreateAsync(It.IsAny<ContentScanLog>()))
            .Callback<ContentScanLog>(log => captured = log).ReturnsAsync((ContentScanLog log) => log);
        _reporting.Setup(reporting => reporting.ReportAsync(It.IsAny<ContentScanLog>(), default))
            .Callback<ContentScanLog, CancellationToken>((log, _) => Assert.Same(captured, log)).Returns(Task.CompletedTask);

        var result = await Service.UploadAsync(7, userId, "original.png", Original);

        Assert.Null(result.Image);
        Assert.Equal("Unable to process this image.", result.Error);
        Assert.NotNull(captured);
        Assert.NotEqual(Guid.Empty, captured.Id);
        Assert.Equal(7, captured.WorkspaceId);
        Assert.Equal(userId, captured.UserId);
        Assert.Equal("original.png", captured.OriginalFileName);
        Assert.Equal("image/png", captured.ContentType);
        Assert.Equal(Original.Length, captured.FileSizeBytes);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(Original)), captured.ImageHash);
        Assert.Equal(new Clock().GetUtcNow().UtcDateTime, captured.ScannedAt);
        Assert.Equal("Match", captured.Details);
        _processor.VerifyNoOtherCalls();
        _images.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task UnsupportedBytes_AreRejectedBeforeScanning()
    {
        _formats.Setup(formats => formats.Detect(Original)).Returns((string?)null);
        Assert.NotNull((await Service.UploadAsync(7, 42, "photo.png", Original)).Error);
        _scanner.VerifyNoOtherCalls();
        _images.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task AuditFailure_PropagatesWithoutReportingOrStoringTheRejectedImage()
    {
        var error = new InvalidOperationException("Audit unavailable");
        _scanner.Setup(scanner => scanner.ScanAsync(Original, "image/png", default)).ReturnsAsync(new ContentScanResult(true, 1, "Test"));
        _logs.Setup(logs => logs.CreateAsync(It.IsAny<ContentScanLog>())).ThrowsAsync(error);
        Assert.Same(error, await Assert.ThrowsAsync<InvalidOperationException>(() => Service.UploadAsync(7, 42, "photo.png", Original)));
        _reporting.VerifyNoOtherCalls();
        _processor.VerifyNoOtherCalls();
        _images.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task StorageFailure_DisposesTheStreamAndDoesNotReplayTheUpload()
    {
        Stream? captured = null;
        var error = new InvalidOperationException("Storage unavailable");
        _images.Setup(images => images.StoreAsync(7, "photo.png", "image/png", It.IsAny<Stream>()))
            .Callback<int, string, string, Stream>((_, _, _, stream) => captured = stream).ThrowsAsync(error);
        Assert.Same(error, await Assert.ThrowsAsync<InvalidOperationException>(() => Service.UploadAsync(7, 42, "photo.png", Original)));
        Assert.False(captured!.CanRead);
        _images.Verify(images => images.StoreAsync(7, "photo.png", "image/png", It.IsAny<Stream>()), Times.Once);
    }

    private sealed class Clock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => new(2026, 11, 11, 10, 0, 0, TimeSpan.Zero);
    }
}
