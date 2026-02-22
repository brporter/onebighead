using OneBigHead.Server.Controllers;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using SkiaSharp;
using System.Security.Claims;
using System.Text;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class ImagesControllerTests
{
    private readonly Mock<IImageProvider> _mockImageProvider;
    private readonly Mock<IImageProcessor> _mockImageProcessor;
    private readonly Mock<IContentScanner> _mockContentScanner;
    private readonly Mock<ICsamReportingService> _mockCsamReportingService;
    private readonly Mock<IContentScanLogRepository> _mockScanLogRepository;
    private readonly Mock<ILogger<ImagesController>> _mockLogger;
    private readonly ImagesController _controller;
    private const int TestWorkspaceId = 1;

    // Valid encoded images for testing
    private static readonly byte[] JpegImage = CreateTestImage(SKEncodedImageFormat.Jpeg);
    private static readonly byte[] PngImage = CreateTestImage(SKEncodedImageFormat.Png);
    private static readonly byte[] WebpImage = CreateTestImage(SKEncodedImageFormat.Webp);

    // SkiaSharp can decode GIF but not encode it, so use a minimal valid GIF89a (1x1 red pixel)
    private static readonly byte[] GifImage =
    [
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61, // GIF89a
        0x01, 0x00, 0x01, 0x00,             // 1x1
        0x80, 0x00, 0x00,                   // GCT flag, 2 entries
        0xFF, 0x00, 0x00,                   // Color 0: red
        0x00, 0x00, 0x00,                   // Color 1: black
        0x2C,                               // Image descriptor
        0x00, 0x00, 0x00, 0x00,             // Left=0, Top=0
        0x01, 0x00, 0x01, 0x00,             // 1x1
        0x00,                               // No local color table
        0x02,                               // LZW minimum code size
        0x02, 0x44, 0x01,                   // Sub-block: 2 bytes of LZW data
        0x00,                               // Block terminator
        0x3B                                // Trailer
    ];

    private static byte[] CreateTestImage(SKEncodedImageFormat format)
    {
        using var bitmap = new SKBitmap(1, 1);
        bitmap.SetPixel(0, 0, SKColors.Red);
        using var image = SKImage.FromBitmap(bitmap);
        using var data = image.Encode(format, 75);
        return data!.ToArray();
    }

    public ImagesControllerTests()
    {
        _mockImageProvider = new Mock<IImageProvider>();
        _mockImageProcessor = new Mock<IImageProcessor>();
        _mockContentScanner = new Mock<IContentScanner>();
        _mockCsamReportingService = new Mock<ICsamReportingService>();
        _mockScanLogRepository = new Mock<IContentScanLogRepository>();
        _mockLogger = new Mock<ILogger<ImagesController>>();

        // Default passthrough: return input data unchanged
        _mockImageProcessor
            .Setup(p => p.ResizeIfNeeded(It.IsAny<byte[]>(), It.IsAny<string>()))
            .Returns((byte[] data, string ct) => (data, ct));

        // Default: scanner returns no match
        _mockContentScanner
            .Setup(s => s.ScanAsync(It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ContentScanResult(IsMatch: false, MatchScore: 0.0, ScannerName: "MockScanner"));

        _controller = new ImagesController(
            _mockImageProvider.Object,
            _mockImageProcessor.Object,
            _mockContentScanner.Object,
            _mockCsamReportingService.Object,
            _mockScanLogRepository.Object,
            _mockLogger.Object);
        SetupAuthenticatedUser(TestWorkspaceId);
    }

    private void SetupAuthenticatedUser(int workspaceId)
    {
        var claims = new List<Claim>
        {
            new("workspace_id", workspaceId.ToString()),
            new(ClaimTypes.NameIdentifier, "1"),
            new(ClaimTypes.Email, "test@example.com")
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var claimsPrincipal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = claimsPrincipal }
        };
    }

    private void SetupUnauthenticatedUser()
    {
        var identity = new ClaimsIdentity(); // No claims
        var claimsPrincipal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = claimsPrincipal }
        };
    }

    private static IFormFile CreateMockFile(byte[] content, string fileName, string contentType)
    {
        var stream = new MemoryStream(content);
        return new FormFile(stream, 0, content.Length, "file", fileName)
        {
            Headers = new HeaderDictionary(),
            ContentType = contentType
        };
    }

    #region Upload Tests

    [Fact]
    public async Task Upload_ReturnsOk_WithValidJpegFile()
    {
        // Arrange
        var imageKey = Guid.NewGuid();
        var file = CreateMockFile(JpegImage, "test.jpg", "image/jpeg");
        _mockImageProvider.Setup(p => p.StoreAsync(TestWorkspaceId, It.IsAny<string>(), "image/jpeg", It.IsAny<Stream>()))
            .ReturnsAsync(new StoredImageInfo(imageKey, $"/api/images/{imageKey}"));

        // Act
        var result = await _controller.Upload(file);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<ImageUploadResponse>(okResult.Value);
        Assert.Equal(imageKey, response.Key);
        Assert.Equal($"/api/images/{imageKey}", response.Url);
    }

    [Fact]
    public async Task Upload_ReturnsOk_WithValidPngFile()
    {
        // Arrange
        var imageKey = Guid.NewGuid();
        var file = CreateMockFile(PngImage, "test.png", "image/png");
        _mockImageProvider.Setup(p => p.StoreAsync(TestWorkspaceId, It.IsAny<string>(), "image/png", It.IsAny<Stream>()))
            .ReturnsAsync(new StoredImageInfo(imageKey, $"/api/images/{imageKey}"));

        // Act
        var result = await _controller.Upload(file);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        Assert.NotNull(okResult.Value);
    }

    [Fact]
    public async Task Upload_ReturnsOk_WithValidGifFile()
    {
        // Arrange
        var imageKey = Guid.NewGuid();
        var file = CreateMockFile(GifImage, "test.gif", "image/gif");
        _mockImageProvider.Setup(p => p.StoreAsync(TestWorkspaceId, It.IsAny<string>(), "image/gif", It.IsAny<Stream>()))
            .ReturnsAsync(new StoredImageInfo(imageKey, $"/api/images/{imageKey}"));

        // Act
        var result = await _controller.Upload(file);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        Assert.NotNull(okResult.Value);
    }

    [Fact]
    public async Task Upload_ReturnsOk_WithValidWebpFile()
    {
        // Arrange
        var imageKey = Guid.NewGuid();
        var file = CreateMockFile(WebpImage, "test.webp", "image/webp");
        _mockImageProvider.Setup(p => p.StoreAsync(TestWorkspaceId, It.IsAny<string>(), "image/webp", It.IsAny<Stream>()))
            .ReturnsAsync(new StoredImageInfo(imageKey, $"/api/images/{imageKey}"));

        // Act
        var result = await _controller.Upload(file);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        Assert.NotNull(okResult.Value);
    }

    [Fact]
    public async Task Upload_ReturnsBadRequest_WhenNoFileProvided()
    {
        // Act
        var result = await _controller.Upload(null!);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
        Assert.Contains("No file provided", badRequestResult.Value?.ToString());
    }

    [Fact]
    public async Task Upload_ReturnsBadRequest_WhenEmptyFileProvided()
    {
        // Arrange
        var file = CreateMockFile(Array.Empty<byte>(), "empty.jpg", "image/jpeg");

        // Act
        var result = await _controller.Upload(file);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
        Assert.Contains("No file provided", badRequestResult.Value?.ToString());
    }

    [Fact]
    public async Task Upload_ReturnsBadRequest_WhenFileIsNotAValidImage()
    {
        // Arrange - Random bytes that aren't a valid image
        var invalidContent = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
        var file = CreateMockFile(invalidContent, "invalid.jpg", "image/jpeg");

        // Act
        var result = await _controller.Upload(file);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
        Assert.Contains("not a valid image", badRequestResult.Value?.ToString());
    }

    [Fact]
    public async Task Upload_ReturnsBadRequest_WhenSvgFileProvided()
    {
        // Arrange - SVG is XML, not decodable by SkiaSharp
        var file = CreateMockFile(Encoding.UTF8.GetBytes("<svg></svg>"), "test.svg", "image/svg+xml");

        // Act
        var result = await _controller.Upload(file);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
        Assert.Contains("not a valid image", badRequestResult.Value?.ToString());
    }

    [Fact]
    public async Task Upload_ReturnsBadRequest_WhenTextFileRenamedToJpg()
    {
        // Arrange - Plain text file pretending to be a JPEG
        var file = CreateMockFile(Encoding.UTF8.GetBytes("This is not an image"), "fake.jpg", "image/jpeg");

        // Act
        var result = await _controller.Upload(file);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
        Assert.Contains("not a valid image", badRequestResult.Value?.ToString());
    }

    [Fact]
    public async Task Upload_DetectsRealFormat_WhenDeclaredTypeMismatches()
    {
        // Arrange - A real PNG file declared as image/jpeg should succeed
        // and the detected type (image/png) should be stored
        var imageKey = Guid.NewGuid();
        string? capturedContentType = null;
        _mockImageProvider.Setup(p => p.StoreAsync(TestWorkspaceId, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<Stream>()))
            .Callback<int, string, string, Stream>((_, _, contentType, _) => capturedContentType = contentType)
            .ReturnsAsync(new StoredImageInfo(imageKey, $"/api/images/{imageKey}"));

        var file = CreateMockFile(PngImage, "mislabeled.jpg", "image/jpeg");

        // Act
        var result = await _controller.Upload(file);

        // Assert
        Assert.IsType<OkObjectResult>(result.Result);
        Assert.Equal("image/png", capturedContentType);
    }

    [Fact]
    public async Task Upload_StoresDetectedContentType_NotDeclaredType()
    {
        // Arrange
        var imageKey = Guid.NewGuid();
        string? capturedContentType = null;
        _mockImageProvider.Setup(p => p.StoreAsync(TestWorkspaceId, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<Stream>()))
            .Callback<int, string, string, Stream>((_, _, contentType, _) => capturedContentType = contentType)
            .ReturnsAsync(new StoredImageInfo(imageKey, $"/api/images/{imageKey}"));

        // Declare as application/octet-stream but data is a valid JPEG
        var file = CreateMockFile(JpegImage, "test.bin", "application/octet-stream");

        // Act
        var result = await _controller.Upload(file);

        // Assert
        Assert.IsType<OkObjectResult>(result.Result);
        Assert.Equal("image/jpeg", capturedContentType);
    }

    [Fact]
    public async Task Upload_ReturnsUnauthorized_WhenWorkspaceIdMissing()
    {
        // Arrange
        SetupUnauthenticatedUser();
        var file = CreateMockFile(JpegImage, "test.jpg", "image/jpeg");

        // Act
        var result = await _controller.Upload(file);

        // Assert
        Assert.IsType<UnauthorizedObjectResult>(result.Result);
    }

    [Fact]
    public async Task Upload_SanitizesFileName_WithUnsafeCharacters()
    {
        // Arrange
        var imageKey = Guid.NewGuid();
        string? capturedFileName = null;
        _mockImageProvider.Setup(p => p.StoreAsync(TestWorkspaceId, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<Stream>()))
            .Callback<int, string, string, Stream>((_, fileName, _, _) => capturedFileName = fileName)
            .ReturnsAsync(new StoredImageInfo(imageKey, $"/api/images/{imageKey}"));

        var file = CreateMockFile(JpegImage, "../../../etc/passwd.jpg", "image/jpeg");

        // Act
        await _controller.Upload(file);

        // Assert
        Assert.NotNull(capturedFileName);
        Assert.DoesNotContain("..", capturedFileName);
        Assert.DoesNotContain("/", capturedFileName);
        Assert.DoesNotContain("\\", capturedFileName);
    }

    [Fact]
    public async Task Upload_SanitizesFileName_WithNullBytes()
    {
        // Arrange
        var imageKey = Guid.NewGuid();
        string? capturedFileName = null;
        _mockImageProvider.Setup(p => p.StoreAsync(TestWorkspaceId, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<Stream>()))
            .Callback<int, string, string, Stream>((_, fileName, _, _) => capturedFileName = fileName)
            .ReturnsAsync(new StoredImageInfo(imageKey, $"/api/images/{imageKey}"));

        // Create filename with actual null byte
        var fileNameWithNull = "test" + '\0' + ".jpg";
        var file = CreateMockFile(JpegImage, fileNameWithNull, "image/jpeg");

        // Act
        await _controller.Upload(file);

        // Assert
        Assert.NotNull(capturedFileName);
        Assert.DoesNotContain('\0', capturedFileName);
    }

    [Fact]
    public async Task Upload_SanitizesFileName_TruncatesLongNames()
    {
        // Arrange
        var imageKey = Guid.NewGuid();
        string? capturedFileName = null;
        _mockImageProvider.Setup(p => p.StoreAsync(TestWorkspaceId, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<Stream>()))
            .Callback<int, string, string, Stream>((_, fileName, _, _) => capturedFileName = fileName)
            .ReturnsAsync(new StoredImageInfo(imageKey, $"/api/images/{imageKey}"));

        var longFileName = new string('a', 300) + ".jpg";
        var file = CreateMockFile(JpegImage, longFileName, "image/jpeg");

        // Act
        await _controller.Upload(file);

        // Assert
        Assert.NotNull(capturedFileName);
        Assert.True(capturedFileName.Length <= 200);
        Assert.EndsWith(".jpg", capturedFileName);
    }

    [Fact]
    public async Task Upload_CallsResizeIfNeeded_BeforeStoring()
    {
        // Arrange
        var imageKey = Guid.NewGuid();
        var processedData = new byte[] { 0x01, 0x02, 0x03 };
        _mockImageProcessor
            .Setup(p => p.ResizeIfNeeded(It.IsAny<byte[]>(), "image/jpeg"))
            .Returns((processedData, "image/jpeg"));
        _mockImageProvider
            .Setup(p => p.StoreAsync(TestWorkspaceId, It.IsAny<string>(), "image/jpeg", It.IsAny<Stream>()))
            .ReturnsAsync(new StoredImageInfo(imageKey, $"/api/images/{imageKey}"));

        var file = CreateMockFile(JpegImage, "test.jpg", "image/jpeg");

        // Act
        await _controller.Upload(file);

        // Assert
        _mockImageProcessor.Verify(p => p.ResizeIfNeeded(It.IsAny<byte[]>(), "image/jpeg"), Times.Once);
        _mockImageProvider.Verify(p => p.StoreAsync(TestWorkspaceId, It.IsAny<string>(), "image/jpeg", It.IsAny<Stream>()), Times.Once);
    }

    [Fact]
    public async Task Upload_ReturnsBadRequest_WhenContentScannerDetectsMatch()
    {
        // Arrange
        _mockContentScanner
            .Setup(s => s.ScanAsync(It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ContentScanResult(IsMatch: true, MatchScore: 0.99, ScannerName: "TestScanner", Details: "test match"));
        _mockScanLogRepository
            .Setup(r => r.CreateAsync(It.IsAny<ContentScanLog>()))
            .ReturnsAsync((ContentScanLog log) => log);

        var file = CreateMockFile(JpegImage, "test.jpg", "image/jpeg");

        // Act
        var result = await _controller.Upload(file);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
        Assert.Contains("Unable to process this image", badRequestResult.Value?.ToString());
        // Should NOT reveal CSAM detection details
        Assert.DoesNotContain("match", badRequestResult.Value?.ToString() ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Upload_LogsScanResult_WhenMatchDetected()
    {
        // Arrange
        ContentScanLog? capturedLog = null;
        _mockContentScanner
            .Setup(s => s.ScanAsync(It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ContentScanResult(IsMatch: true, MatchScore: 0.95, ScannerName: "TestScanner", Details: "hash match"));
        _mockScanLogRepository
            .Setup(r => r.CreateAsync(It.IsAny<ContentScanLog>()))
            .Callback<ContentScanLog>(log => capturedLog = log)
            .ReturnsAsync((ContentScanLog log) => log);

        var file = CreateMockFile(JpegImage, "malicious.jpg", "image/jpeg");

        // Act
        await _controller.Upload(file);

        // Assert
        Assert.NotNull(capturedLog);
        Assert.True(capturedLog.IsMatch);
        Assert.Equal(0.95, capturedLog.MatchScore);
        Assert.Equal("TestScanner", capturedLog.ScannerName);
        Assert.Equal("hash match", capturedLog.Details);
        Assert.Equal(TestWorkspaceId, capturedLog.WorkspaceId);
        Assert.Equal("malicious.jpg", capturedLog.OriginalFileName);
        Assert.Equal("image/jpeg", capturedLog.ContentType);
        Assert.Equal(JpegImage.Length, capturedLog.FileSizeBytes);
        Assert.NotNull(capturedLog.ImageHash);
    }

    [Fact]
    public async Task Upload_CallsReportingService_WhenMatchDetected()
    {
        // Arrange
        _mockContentScanner
            .Setup(s => s.ScanAsync(It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ContentScanResult(IsMatch: true, MatchScore: 0.99, ScannerName: "TestScanner"));
        _mockScanLogRepository
            .Setup(r => r.CreateAsync(It.IsAny<ContentScanLog>()))
            .ReturnsAsync((ContentScanLog log) => log);

        var file = CreateMockFile(JpegImage, "test.jpg", "image/jpeg");

        // Act
        await _controller.Upload(file);

        // Assert
        _mockCsamReportingService.Verify(
            s => s.ReportAsync(It.IsAny<ContentScanLog>(), It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task Upload_ReturnsBadRequest_WhenReportingServiceThrows()
    {
        // Arrange - Scanner detects a match, but reporting service throws
        _mockContentScanner
            .Setup(s => s.ScanAsync(It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ContentScanResult(IsMatch: true, MatchScore: 0.99, ScannerName: "TestScanner"));
        _mockScanLogRepository
            .Setup(r => r.CreateAsync(It.IsAny<ContentScanLog>()))
            .ReturnsAsync((ContentScanLog log) => log);
        _mockCsamReportingService
            .Setup(s => s.ReportAsync(It.IsAny<ContentScanLog>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Reporting API unavailable"));

        var file = CreateMockFile(JpegImage, "test.jpg", "image/jpeg");

        // Act
        var result = await _controller.Upload(file);

        // Assert - should still return BadRequest, not 500
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
        Assert.Contains("Unable to process this image", badRequestResult.Value?.ToString());
        // Scan log should still have been created
        _mockScanLogRepository.Verify(r => r.CreateAsync(It.IsAny<ContentScanLog>()), Times.Once);
    }

    [Fact]
    public async Task Upload_Succeeds_WhenScannerReturnsNoMatch()
    {
        // Arrange
        var imageKey = Guid.NewGuid();
        _mockContentScanner
            .Setup(s => s.ScanAsync(It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ContentScanResult(IsMatch: false, MatchScore: 0.0, ScannerName: "TestScanner"));
        _mockImageProvider
            .Setup(p => p.StoreAsync(TestWorkspaceId, It.IsAny<string>(), "image/jpeg", It.IsAny<Stream>()))
            .ReturnsAsync(new StoredImageInfo(imageKey, $"/api/images/{imageKey}"));

        var file = CreateMockFile(JpegImage, "test.jpg", "image/jpeg");

        // Act
        var result = await _controller.Upload(file);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<ImageUploadResponse>(okResult.Value);
        Assert.Equal(imageKey, response.Key);
        // Should NOT log or report when no match
        _mockScanLogRepository.Verify(r => r.CreateAsync(It.IsAny<ContentScanLog>()), Times.Never);
        _mockCsamReportingService.Verify(s => s.ReportAsync(It.IsAny<ContentScanLog>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Upload_ScansBeforeResize()
    {
        // Arrange
        var scanCallOrder = 0;
        var resizeCallOrder = 0;
        var callCounter = 0;

        _mockContentScanner
            .Setup(s => s.ScanAsync(It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Callback(() => scanCallOrder = ++callCounter)
            .ReturnsAsync(new ContentScanResult(IsMatch: false, MatchScore: 0.0, ScannerName: "TestScanner"));
        _mockImageProcessor
            .Setup(p => p.ResizeIfNeeded(It.IsAny<byte[]>(), It.IsAny<string>()))
            .Callback(() => resizeCallOrder = ++callCounter)
            .Returns((byte[] data, string ct) => (data, ct));
        _mockImageProvider
            .Setup(p => p.StoreAsync(TestWorkspaceId, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<Stream>()))
            .ReturnsAsync(new StoredImageInfo(Guid.NewGuid(), "/api/images/test"));

        var file = CreateMockFile(JpegImage, "test.jpg", "image/jpeg");

        // Act
        await _controller.Upload(file);

        // Assert - scan must happen before resize
        Assert.True(scanCallOrder > 0, "Scanner should have been called");
        Assert.True(resizeCallOrder > 0, "Resize should have been called");
        Assert.True(scanCallOrder < resizeCallOrder, "Scanner should be called before resize");
    }

    [Fact]
    public async Task Upload_HandlesScanner_Exception_Gracefully()
    {
        // Arrange - Scanner throws an exception (e.g. API timeout)
        _mockContentScanner
            .Setup(s => s.ScanAsync(It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Scanner API timeout"));

        var file = CreateMockFile(JpegImage, "test.jpg", "image/jpeg");

        // Act
        var result = await _controller.Upload(file);

        // Assert - fail-closed: reject the upload
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
        Assert.Contains("Unable to process this image", badRequestResult.Value?.ToString());
        // Should NOT have stored the image
        _mockImageProvider.Verify(
            p => p.StoreAsync(It.IsAny<int>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<Stream>()),
            Times.Never);
    }

    [Fact]
    public async Task Upload_DoesNotCallResize_WhenScannerDetectsMatch()
    {
        // Arrange
        _mockContentScanner
            .Setup(s => s.ScanAsync(It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ContentScanResult(IsMatch: true, MatchScore: 0.99, ScannerName: "TestScanner"));
        _mockScanLogRepository
            .Setup(r => r.CreateAsync(It.IsAny<ContentScanLog>()))
            .ReturnsAsync((ContentScanLog log) => log);

        var file = CreateMockFile(JpegImage, "test.jpg", "image/jpeg");

        // Act
        await _controller.Upload(file);

        // Assert - should not proceed to resize or store
        _mockImageProcessor.Verify(p => p.ResizeIfNeeded(It.IsAny<byte[]>(), It.IsAny<string>()), Times.Never);
        _mockImageProvider.Verify(
            p => p.StoreAsync(It.IsAny<int>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<Stream>()),
            Times.Never);
    }

    #endregion

    #region Get Tests

    [Fact]
    public async Task Get_ReturnsFile_WhenAuthenticatedAndImageExistsInWorkspace()
    {
        // Arrange
        var imageKey = Guid.NewGuid();
        var imageData = new byte[] { 0xFF, 0xD8, 0xFF };
        _mockImageProvider.Setup(p => p.RetrieveAsync(imageKey, TestWorkspaceId))
            .ReturnsAsync(new RetrievedImage(imageData, "image/jpeg", "test.jpg"));

        // Act
        var result = await _controller.Get(imageKey);

        // Assert
        var fileResult = Assert.IsType<FileContentResult>(result);
        Assert.Equal("image/jpeg", fileResult.ContentType);
        Assert.Equal("test.jpg", fileResult.FileDownloadName);
        Assert.Equal(imageData, fileResult.FileContents);
    }

    [Fact]
    public async Task Get_ReturnsNotFound_WhenAuthenticatedAndImageDoesNotExist()
    {
        // Arrange
        var imageKey = Guid.NewGuid();
        _mockImageProvider.Setup(p => p.RetrieveAsync(imageKey, TestWorkspaceId))
            .ReturnsAsync((RetrievedImage?)null);
        _mockImageProvider.Setup(p => p.RetrievePublicAsync(imageKey))
            .ReturnsAsync((RetrievedImage?)null);

        // Act
        var result = await _controller.Get(imageKey);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Get_FallsBackToPublic_WhenAuthenticatedButNotInWorkspace()
    {
        // Arrange
        var imageKey = Guid.NewGuid();
        var imageData = new byte[] { 0xFF, 0xD8, 0xFF };
        // Not found in user's workspace
        _mockImageProvider.Setup(p => p.RetrieveAsync(imageKey, TestWorkspaceId))
            .ReturnsAsync((RetrievedImage?)null);
        // But available publicly
        _mockImageProvider.Setup(p => p.RetrievePublicAsync(imageKey))
            .ReturnsAsync(new RetrievedImage(imageData, "image/jpeg", "test.jpg"));

        // Act
        var result = await _controller.Get(imageKey);

        // Assert
        var fileResult = Assert.IsType<FileContentResult>(result);
        Assert.Equal("image/jpeg", fileResult.ContentType);
    }

    [Fact]
    public async Task Get_ReturnsFile_WhenUnauthenticatedAndImageIsPublic()
    {
        // Arrange
        SetupUnauthenticatedUser();
        var imageKey = Guid.NewGuid();
        var imageData = new byte[] { 0xFF, 0xD8, 0xFF };
        _mockImageProvider.Setup(p => p.RetrievePublicAsync(imageKey))
            .ReturnsAsync(new RetrievedImage(imageData, "image/jpeg", "test.jpg"));

        // Act
        var result = await _controller.Get(imageKey);

        // Assert
        var fileResult = Assert.IsType<FileContentResult>(result);
        Assert.Equal("image/jpeg", fileResult.ContentType);
    }

    [Fact]
    public async Task Get_ReturnsNotFound_WhenUnauthenticatedAndImageIsNotPublic()
    {
        // Arrange
        SetupUnauthenticatedUser();
        var imageKey = Guid.NewGuid();
        _mockImageProvider.Setup(p => p.RetrievePublicAsync(imageKey))
            .ReturnsAsync((RetrievedImage?)null);

        // Act
        var result = await _controller.Get(imageKey);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Get_PassesWorkspaceIdToProvider_WhenAuthenticated()
    {
        // Arrange
        var imageKey = Guid.NewGuid();
        _mockImageProvider.Setup(p => p.RetrieveAsync(imageKey, TestWorkspaceId))
            .ReturnsAsync(new RetrievedImage(new byte[] { 0xFF }, "image/jpeg", "test.jpg"));

        // Act
        await _controller.Get(imageKey);

        // Assert
        _mockImageProvider.Verify(p => p.RetrieveAsync(imageKey, TestWorkspaceId), Times.Once);
    }

    #endregion

    #region Delete Tests

    [Fact]
    public async Task Delete_ReturnsNoContent_WhenSuccessful()
    {
        // Arrange
        var imageKey = Guid.NewGuid();
        _mockImageProvider.Setup(p => p.DeleteAsync(imageKey, TestWorkspaceId))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _controller.Delete(imageKey);

        // Assert
        Assert.IsType<NoContentResult>(result);
    }

    [Fact]
    public async Task Delete_ReturnsUnauthorized_WhenWorkspaceIdMissing()
    {
        // Arrange
        SetupUnauthenticatedUser();
        var imageKey = Guid.NewGuid();

        // Act
        var result = await _controller.Delete(imageKey);

        // Assert
        Assert.IsType<UnauthorizedObjectResult>(result);
    }

    [Fact]
    public async Task Delete_PassesWorkspaceIdToProvider()
    {
        // Arrange
        var imageKey = Guid.NewGuid();
        _mockImageProvider.Setup(p => p.DeleteAsync(imageKey, TestWorkspaceId))
            .Returns(Task.CompletedTask);

        // Act
        await _controller.Delete(imageKey);

        // Assert
        _mockImageProvider.Verify(p => p.DeleteAsync(imageKey, TestWorkspaceId), Times.Once);
    }

    #endregion
}
