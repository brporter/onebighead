using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Moq;
using OneBigHead.Server.Middleware;

namespace OneBigHead.Server.Tests.Middleware;

[Trait("Category", "Unit")]
public class GlobalExceptionHandlerTests
{
    private readonly Mock<ILogger<GlobalExceptionHandler>> _mockLogger;
    private readonly Mock<IHostEnvironment> _mockEnvironment;
    private readonly GlobalExceptionHandler _handler;

    public GlobalExceptionHandlerTests()
    {
        _mockLogger = new Mock<ILogger<GlobalExceptionHandler>>();
        _mockEnvironment = new Mock<IHostEnvironment>();
        _handler = new GlobalExceptionHandler(_mockLogger.Object, _mockEnvironment.Object);
    }

    private static HttpContext CreateHttpContext()
    {
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/test";
        context.Request.Method = "GET";
        context.Response.Body = new MemoryStream();
        return context;
    }

    private async Task<string> GetResponseBodyAsync(HttpContext context)
    {
        context.Response.Body.Seek(0, SeekOrigin.Begin);
        using var reader = new StreamReader(context.Response.Body);
        return await reader.ReadToEndAsync();
    }

    [Fact]
    public async Task TryHandleAsync_ReturnsTrue_WhenExceptionHandled()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Production");
        var context = CreateHttpContext();
        var exception = new Exception("Test exception");

        // Act
        var result = await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task TryHandleAsync_Returns500_ForGenericException()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Production");
        var context = CreateHttpContext();
        var exception = new Exception("Test exception");

        // Act
        await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        Assert.Equal(StatusCodes.Status500InternalServerError, context.Response.StatusCode);
        Assert.StartsWith("application/json", context.Response.ContentType);
    }

    [Fact]
    public async Task TryHandleAsync_Returns401_ForUnauthorizedAccessException()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Production");
        var context = CreateHttpContext();
        var exception = new UnauthorizedAccessException("Not authorized");

        // Act
        await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryHandleAsync_Returns400_ForArgumentException()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Production");
        var context = CreateHttpContext();
        var exception = new ArgumentException("Invalid argument");

        // Act
        await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryHandleAsync_Returns404_ForKeyNotFoundException()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Production");
        var context = CreateHttpContext();
        var exception = new KeyNotFoundException("Resource not found");

        // Act
        await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        Assert.Equal(StatusCodes.Status404NotFound, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryHandleAsync_Returns400_ForInvalidOperationException()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Production");
        var context = CreateHttpContext();
        var exception = new InvalidOperationException("Invalid operation");

        // Act
        await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryHandleAsync_IncludesTraceId_InResponse()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Production");
        var context = CreateHttpContext();
        context.TraceIdentifier = "test-trace-id-123";
        var exception = new Exception("Test exception");

        // Act
        await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        var responseBody = await GetResponseBodyAsync(context);
        Assert.Contains("test-trace-id-123", responseBody);
    }

    [Fact]
    public async Task TryHandleAsync_Production_DoesNotIncludeExceptionDetails()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Production");
        var context = CreateHttpContext();
        var exception = new Exception("Sensitive error details");

        // Act
        await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        var responseBody = await GetResponseBodyAsync(context);
        Assert.DoesNotContain("Sensitive error details", responseBody);
    }

    [Fact]
    public async Task TryHandleAsync_Development_IncludesExceptionDetails()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Development");
        var context = CreateHttpContext();
        var exception = new Exception("Detailed error message");

        // Act
        await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        var responseBody = await GetResponseBodyAsync(context);
        Assert.Contains("Detailed error message", responseBody);
    }

    [Fact]
    public async Task TryHandleAsync_Development_IncludesStackTrace()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Development");
        var context = CreateHttpContext();
        Exception? caughtException = null;

        try
        {
            throw new Exception("Test exception");
        }
        catch (Exception ex)
        {
            caughtException = ex;
        }

        // Act
        await _handler.TryHandleAsync(context, caughtException!, CancellationToken.None);

        // Assert
        var responseBody = await GetResponseBodyAsync(context);
        Assert.Contains("stackTrace", responseBody);
    }

    [Fact]
    public async Task TryHandleAsync_LogsException_WithDetails()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Production");
        var context = CreateHttpContext();
        context.Request.Path = "/api/test/path";
        context.Request.Method = "POST";
        context.TraceIdentifier = "trace-123";
        var exception = new Exception("Test exception message");

        // Act
        await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString()!.Contains("trace-123")),
                exception,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task TryHandleAsync_ResponseContainsCorrectMessage_ForUnauthorized()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Production");
        var context = CreateHttpContext();
        var exception = new UnauthorizedAccessException();

        // Act
        await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        var responseBody = await GetResponseBodyAsync(context);
        Assert.Contains("Unauthorized access", responseBody);
    }

    [Fact]
    public async Task TryHandleAsync_ResponseContainsCorrectMessage_ForNotFound()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Production");
        var context = CreateHttpContext();
        var exception = new KeyNotFoundException();

        // Act
        await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        var responseBody = await GetResponseBodyAsync(context);
        Assert.Contains("Resource not found", responseBody);
    }

    [Fact]
    public async Task TryHandleAsync_ResponseContainsCorrectMessage_ForBadRequest()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Production");
        var context = CreateHttpContext();
        var exception = new ArgumentException();

        // Act
        await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        var responseBody = await GetResponseBodyAsync(context);
        Assert.Contains("Invalid request", responseBody);
    }

    [Fact]
    public async Task TryHandleAsync_ResponseContainsCorrectMessage_ForGenericError()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Production");
        var context = CreateHttpContext();
        var exception = new Exception();

        // Act
        await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        var responseBody = await GetResponseBodyAsync(context);
        Assert.Contains("An unexpected error occurred", responseBody);
    }
}
