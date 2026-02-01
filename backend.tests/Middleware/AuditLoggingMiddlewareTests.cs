using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using OneBigHead.Server.Middleware;

namespace OneBigHead.Server.Tests.Middleware;

[Trait("Category", "Unit")]
public class AuditLoggingMiddlewareTests
{
    private readonly Mock<ILogger<AuditLoggingMiddleware>> _mockLogger;
    private readonly RequestDelegate _nextDelegate;
    private bool _nextDelegateCalled;

    public AuditLoggingMiddlewareTests()
    {
        _mockLogger = new Mock<ILogger<AuditLoggingMiddleware>>();
        _nextDelegateCalled = false;
        _nextDelegate = context =>
        {
            _nextDelegateCalled = true;
            context.Response.StatusCode = 200;
            return Task.CompletedTask;
        };
    }

    private HttpContext CreateHttpContext(
        string method = "GET",
        string path = "/api/test",
        int? userId = null,
        int? tenantId = null,
        string? email = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;

        if (userId.HasValue || tenantId.HasValue || email != null)
        {
            var claims = new List<Claim>();
            if (userId.HasValue)
            {
                claims.Add(new Claim(ClaimTypes.NameIdentifier, userId.Value.ToString()));
            }
            if (tenantId.HasValue)
            {
                claims.Add(new Claim("tenant_id", tenantId.Value.ToString()));
            }
            if (email != null)
            {
                claims.Add(new Claim(ClaimTypes.Email, email));
            }
            context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"));
        }

        return context;
    }

    #region Non-State-Changing Methods (GET, HEAD, OPTIONS)

    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    [InlineData("OPTIONS")]
    public async Task InvokeAsync_SkipsLogging_ForNonStateChangingMethods(string method)
    {
        // Arrange
        var middleware = new AuditLoggingMiddleware(_nextDelegate, _mockLogger.Object);
        var context = CreateHttpContext(method: method, path: "/api/users");

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        Assert.True(_nextDelegateCalled);
        _mockLogger.Verify(
            x => x.Log(
                It.IsAny<LogLevel>(),
                It.IsAny<EventId>(),
                It.IsAny<It.IsAnyType>(),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Never);
    }

    #endregion

    #region State-Changing Methods (POST, PUT, PATCH, DELETE)

    [Theory]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("PATCH")]
    [InlineData("DELETE")]
    public async Task InvokeAsync_LogsAudit_ForStateChangingMethods_OnAuditedPaths(string method)
    {
        // Arrange
        var middleware = new AuditLoggingMiddleware(_nextDelegate, _mockLogger.Object);
        var context = CreateHttpContext(
            method: method,
            path: "/api/users",
            userId: 123,
            tenantId: 456,
            email: "test@example.com");

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        Assert.True(_nextDelegateCalled);
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString()!.Contains("Audit:")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.AtLeast(1));
    }

    #endregion

    #region Path Matching

    [Theory]
    [InlineData("/api/users")]
    [InlineData("/api/users/123")]
    [InlineData("/api/tenants")]
    [InlineData("/api/tenants/1/settings")]
    [InlineData("/api/collections")]
    [InlineData("/api/collections/1")]
    [InlineData("/api/categories")]
    [InlineData("/api/categories/5")]
    [InlineData("/api/items")]
    [InlineData("/api/items/10")]
    [InlineData("/api/templates")]
    [InlineData("/api/templates/2")]
    [InlineData("/api/admin")]
    [InlineData("/api/admin/support")]
    [InlineData("/api/auth/accept-terms")]
    [InlineData("/api/auth/complete-welcome")]
    public async Task InvokeAsync_LogsAudit_ForAuditedPaths(string path)
    {
        // Arrange
        var middleware = new AuditLoggingMiddleware(_nextDelegate, _mockLogger.Object);
        var context = CreateHttpContext(method: "POST", path: path, userId: 1);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString()!.Contains("Audit:")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.AtLeast(1));
    }

    [Theory]
    [InlineData("/api/health")]
    [InlineData("/api/support")]
    [InlineData("/api/auth/login")]
    [InlineData("/api/auth/callback")]
    [InlineData("/some/other/path")]
    public async Task InvokeAsync_SkipsLogging_ForNonAuditedPaths(string path)
    {
        // Arrange
        var middleware = new AuditLoggingMiddleware(_nextDelegate, _mockLogger.Object);
        var context = CreateHttpContext(method: "POST", path: path);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        Assert.True(_nextDelegateCalled);
        _mockLogger.Verify(
            x => x.Log(
                It.IsAny<LogLevel>(),
                It.IsAny<EventId>(),
                It.IsAny<It.IsAnyType>(),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Never);
    }

    #endregion

    #region User Information Extraction

    [Fact]
    public async Task InvokeAsync_LogsUserId_WhenPresent()
    {
        // Arrange
        var middleware = new AuditLoggingMiddleware(_nextDelegate, _mockLogger.Object);
        var context = CreateHttpContext(method: "POST", path: "/api/users", userId: 999);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString()!.Contains("999")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.AtLeast(1));
    }

    [Fact]
    public async Task InvokeAsync_LogsAnonymous_WhenNoUserClaim()
    {
        // Arrange
        var middleware = new AuditLoggingMiddleware(_nextDelegate, _mockLogger.Object);
        var context = CreateHttpContext(method: "POST", path: "/api/users");

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString()!.Contains("anonymous")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.AtLeast(1));
    }

    [Fact]
    public async Task InvokeAsync_LogsTenantId_WhenPresent()
    {
        // Arrange
        var middleware = new AuditLoggingMiddleware(_nextDelegate, _mockLogger.Object);
        var context = CreateHttpContext(method: "POST", path: "/api/users", tenantId: 789);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString()!.Contains("789")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.AtLeast(1));
    }

    [Fact]
    public async Task InvokeAsync_LogsEmail_WhenPresent()
    {
        // Arrange
        var middleware = new AuditLoggingMiddleware(_nextDelegate, _mockLogger.Object);
        var context = CreateHttpContext(method: "POST", path: "/api/users", email: "audit@test.com");

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString()!.Contains("audit@test.com")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.AtLeast(1));
    }

    #endregion

    #region Success/Failure Logging

    [Theory]
    [InlineData(200)]
    [InlineData(201)]
    [InlineData(204)]
    public async Task InvokeAsync_LogsInformation_ForSuccessfulResponses(int statusCode)
    {
        // Arrange
        RequestDelegate nextWithStatus = context =>
        {
            context.Response.StatusCode = statusCode;
            return Task.CompletedTask;
        };
        var middleware = new AuditLoggingMiddleware(nextWithStatus, _mockLogger.Object);
        var context = CreateHttpContext(method: "POST", path: "/api/users", userId: 1);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString()!.Contains("completed")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Theory]
    [InlineData(400)]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(404)]
    [InlineData(500)]
    public async Task InvokeAsync_LogsWarning_ForFailedResponses(int statusCode)
    {
        // Arrange
        RequestDelegate nextWithStatus = context =>
        {
            context.Response.StatusCode = statusCode;
            return Task.CompletedTask;
        };
        var middleware = new AuditLoggingMiddleware(nextWithStatus, _mockLogger.Object);
        var context = CreateHttpContext(method: "POST", path: "/api/users", userId: 1);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString()!.Contains("failed")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    #endregion

    #region Path Matching Edge Cases

    [Fact]
    public async Task InvokeAsync_MatchesPath_CaseInsensitively()
    {
        // Arrange
        var middleware = new AuditLoggingMiddleware(_nextDelegate, _mockLogger.Object);
        var context = CreateHttpContext(method: "POST", path: "/API/USERS", userId: 1);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString()!.Contains("Audit:")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.AtLeast(1));
    }

    [Fact]
    public async Task InvokeAsync_HandleEmptyPath_Gracefully()
    {
        // Arrange
        var middleware = new AuditLoggingMiddleware(_nextDelegate, _mockLogger.Object);
        var context = CreateHttpContext(method: "POST", path: "");

        // Act
        await middleware.InvokeAsync(context);

        // Assert - should not log for empty path and should call next
        Assert.True(_nextDelegateCalled);
    }

    #endregion

    #region Method Case Sensitivity

    [Theory]
    [InlineData("post")]
    [InlineData("Post")]
    [InlineData("POST")]
    public async Task InvokeAsync_MatchesMethod_CaseInsensitively(string method)
    {
        // Arrange
        var middleware = new AuditLoggingMiddleware(_nextDelegate, _mockLogger.Object);
        var context = CreateHttpContext(method: method, path: "/api/users", userId: 1);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString()!.Contains("Audit:")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.AtLeast(1));
    }

    #endregion

    #region Extension Methods

    [Fact]
    public void UseAuditLogging_RegistersMiddleware()
    {
        // This is a basic test to ensure the extension method exists and compiles
        // Full integration testing is done via integration tests
        var method = typeof(AuditLoggingMiddlewareExtensions)
            .GetMethod("UseAuditLogging");

        Assert.NotNull(method);
        Assert.True(method.IsStatic);
    }

    #endregion
}
