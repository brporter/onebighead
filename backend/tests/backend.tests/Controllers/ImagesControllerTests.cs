using OneBigHead.Server.Controllers;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Security.Claims;
using System.Text;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class ImagesControllerTests
{
    private readonly Mock<IImageProvider> _mockImageProvider;
    private readonly Mock<IImageProcessor> _mockImageProcessor;
    private readonly ImagesController _controller;
    private const int TestWorkspaceId = 1;
    private const int OtherWorkspaceId = 2;

    // Valid file signatures for testing
    private static readonly byte[] JpegSignature = { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46 };
    private static readonly byte[] PngSignature = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
    private static readonly byte[] GifSignature = { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 };
    private static readonly byte[] WebpSignature = { 0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50 };

    public ImagesControllerTests()
    {
        _mockImageProvider = new Mock<IImageProvider>();
        _mockImageProcessor = new Mock<IImageProcessor>();
        // Default passthrough: return input data unchanged
        _mockImageProcessor
            .Setup(p => p.ResizeIfNeeded(It.IsAny<byte[]>(), It.IsAny<string>()))
            .Returns((byte[] data, string ct) => (data, ct));
        _controller = new ImagesController(_mockImageProvider.Object, _mockImageProcessor.Object);
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
        var file = CreateMockFile(JpegSignature, "test.jpg", "image/jpeg");
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
        var file = CreateMockFile(PngSignature, "test.png", "image/png");
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
        var file = CreateMockFile(GifSignature, "test.gif", "image/gif");
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
        var file = CreateMockFile(WebpSignature, "test.webp", "image/webp");
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
    public async Task Upload_ReturnsBadRequest_WhenContentTypeNotAllowed()
    {
        // Arrange
        var file = CreateMockFile(Encoding.UTF8.GetBytes("<svg></svg>"), "test.svg", "image/svg+xml");

        // Act
        var result = await _controller.Upload(file);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
        Assert.Contains("not allowed", badRequestResult.Value?.ToString());
    }

    [Fact]
    public async Task Upload_ReturnsBadRequest_WhenFileSignatureDoesNotMatch()
    {
        // Arrange - File claims to be JPEG but has PNG signature
        var file = CreateMockFile(PngSignature, "fake.jpg", "image/jpeg");

        // Act
        var result = await _controller.Upload(file);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
        Assert.Contains("does not match", badRequestResult.Value?.ToString());
    }

    [Fact]
    public async Task Upload_ReturnsBadRequest_WhenFileHasInvalidSignature()
    {
        // Arrange - Random bytes that don't match any known signature
        var invalidContent = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
        var file = CreateMockFile(invalidContent, "invalid.jpg", "image/jpeg");

        // Act
        var result = await _controller.Upload(file);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
        Assert.Contains("does not match", badRequestResult.Value?.ToString());
    }

    [Fact]
    public async Task Upload_ReturnsUnauthorized_WhenWorkspaceIdMissing()
    {
        // Arrange
        SetupUnauthenticatedUser();
        var file = CreateMockFile(JpegSignature, "test.jpg", "image/jpeg");

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
        _mockImageProvider.Setup(p => p.StoreAsync(TestWorkspaceId, It.IsAny<string>(), "image/jpeg", It.IsAny<Stream>()))
            .Callback<int, string, string, Stream>((_, fileName, _, _) => capturedFileName = fileName)
            .ReturnsAsync(new StoredImageInfo(imageKey, $"/api/images/{imageKey}"));

        var file = CreateMockFile(JpegSignature, "../../../etc/passwd.jpg", "image/jpeg");

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
        _mockImageProvider.Setup(p => p.StoreAsync(TestWorkspaceId, It.IsAny<string>(), "image/jpeg", It.IsAny<Stream>()))
            .Callback<int, string, string, Stream>((_, fileName, _, _) => capturedFileName = fileName)
            .ReturnsAsync(new StoredImageInfo(imageKey, $"/api/images/{imageKey}"));

        // Create filename with actual null byte
        var fileNameWithNull = "test" + '\0' + ".jpg";
        var file = CreateMockFile(JpegSignature, fileNameWithNull, "image/jpeg");

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
        _mockImageProvider.Setup(p => p.StoreAsync(TestWorkspaceId, It.IsAny<string>(), "image/jpeg", It.IsAny<Stream>()))
            .Callback<int, string, string, Stream>((_, fileName, _, _) => capturedFileName = fileName)
            .ReturnsAsync(new StoredImageInfo(imageKey, $"/api/images/{imageKey}"));

        var longFileName = new string('a', 300) + ".jpg";
        var file = CreateMockFile(JpegSignature, longFileName, "image/jpeg");

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

        var file = CreateMockFile(JpegSignature, "test.jpg", "image/jpeg");

        // Act
        await _controller.Upload(file);

        // Assert
        _mockImageProcessor.Verify(p => p.ResizeIfNeeded(It.IsAny<byte[]>(), "image/jpeg"), Times.Once);
        _mockImageProvider.Verify(p => p.StoreAsync(TestWorkspaceId, It.IsAny<string>(), "image/jpeg", It.IsAny<Stream>()), Times.Once);
    }

    #endregion

    #region Get Tests

    [Fact]
    public async Task Get_ReturnsFile_WhenImageExists()
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
    public async Task Get_ReturnsNotFound_WhenImageDoesNotExist()
    {
        // Arrange
        var imageKey = Guid.NewGuid();
        _mockImageProvider.Setup(p => p.RetrieveAsync(imageKey, TestWorkspaceId))
            .ReturnsAsync((RetrievedImage?)null);

        // Act
        var result = await _controller.Get(imageKey);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Get_ReturnsNotFound_WhenImageBelongsToDifferentWorkspace()
    {
        // Arrange
        var imageKey = Guid.NewGuid();
        // Image exists but belongs to different workspace - provider returns null due to workspace filter
        _mockImageProvider.Setup(p => p.RetrieveAsync(imageKey, TestWorkspaceId))
            .ReturnsAsync((RetrievedImage?)null);

        // Act
        var result = await _controller.Get(imageKey);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Get_ReturnsUnauthorized_WhenWorkspaceIdMissing()
    {
        // Arrange
        SetupUnauthenticatedUser();
        var imageKey = Guid.NewGuid();

        // Act
        var result = await _controller.Get(imageKey);

        // Assert
        Assert.IsType<UnauthorizedObjectResult>(result);
    }

    [Fact]
    public async Task Get_PassesWorkspaceIdToProvider()
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
