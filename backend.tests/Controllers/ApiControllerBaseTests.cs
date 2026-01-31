using OneBigHead.Server.Controllers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace OneBigHead.Server.Tests.Controllers;

// Concrete implementation to test abstract base class
public class TestableApiController : ApiControllerBase
{
    public int TestGetTenantId() => GetTenantId();
    public int? TestTryGetTenantId() => TryGetTenantId();
    public int TestGetUserId() => GetUserId();
}

[Trait("Category", "Unit")]
public class ApiControllerBaseTests
{
    private readonly TestableApiController _controller;

    public ApiControllerBaseTests()
    {
        _controller = new TestableApiController();
    }

    private void SetupUser(params Claim[] claims)
    {
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var claimsPrincipal = new ClaimsPrincipal(identity);
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = claimsPrincipal }
        };
    }

    #region GetTenantId Tests

    [Fact]
    public void GetTenantId_WithValidClaim_ReturnsTenantId()
    {
        // Arrange
        SetupUser(new Claim("tenant_id", "42"));

        // Act
        var result = _controller.TestGetTenantId();

        // Assert
        Assert.Equal(42, result);
    }

    [Fact]
    public void GetTenantId_WithMissingClaim_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        SetupUser(new Claim("other_claim", "value"));

        // Act & Assert
        var exception = Assert.Throws<UnauthorizedAccessException>(() => _controller.TestGetTenantId());
        Assert.Equal("Tenant ID not found in token", exception.Message);
    }

    [Fact]
    public void GetTenantId_WithEmptyClaim_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        SetupUser(new Claim("tenant_id", ""));

        // Act & Assert
        var exception = Assert.Throws<UnauthorizedAccessException>(() => _controller.TestGetTenantId());
        Assert.Equal("Tenant ID not found in token", exception.Message);
    }

    [Fact]
    public void GetTenantId_WithNonNumericClaim_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        SetupUser(new Claim("tenant_id", "not-a-number"));

        // Act & Assert
        var exception = Assert.Throws<UnauthorizedAccessException>(() => _controller.TestGetTenantId());
        Assert.Equal("Tenant ID not found in token", exception.Message);
    }

    #endregion

    #region TryGetTenantId Tests

    [Fact]
    public void TryGetTenantId_WithValidClaim_ReturnsTenantId()
    {
        // Arrange
        SetupUser(new Claim("tenant_id", "42"));

        // Act
        var result = _controller.TestTryGetTenantId();

        // Assert
        Assert.Equal(42, result);
    }

    [Fact]
    public void TryGetTenantId_WithMissingClaim_ReturnsNull()
    {
        // Arrange
        SetupUser(new Claim("other_claim", "value"));

        // Act
        var result = _controller.TestTryGetTenantId();

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void TryGetTenantId_WithEmptyClaim_ReturnsNull()
    {
        // Arrange
        SetupUser(new Claim("tenant_id", ""));

        // Act
        var result = _controller.TestTryGetTenantId();

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void TryGetTenantId_WithNonNumericClaim_ReturnsNull()
    {
        // Arrange
        SetupUser(new Claim("tenant_id", "not-a-number"));

        // Act
        var result = _controller.TestTryGetTenantId();

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region GetUserId Tests

    [Fact]
    public void GetUserId_WithValidClaim_ReturnsUserId()
    {
        // Arrange
        SetupUser(new Claim(ClaimTypes.NameIdentifier, "123"));

        // Act
        var result = _controller.TestGetUserId();

        // Assert
        Assert.Equal(123, result);
    }

    [Fact]
    public void GetUserId_WithMissingClaim_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        SetupUser(new Claim("other_claim", "value"));

        // Act & Assert
        var exception = Assert.Throws<UnauthorizedAccessException>(() => _controller.TestGetUserId());
        Assert.Equal("User ID not found in token", exception.Message);
    }

    [Fact]
    public void GetUserId_WithEmptyClaim_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        SetupUser(new Claim(ClaimTypes.NameIdentifier, ""));

        // Act & Assert
        var exception = Assert.Throws<UnauthorizedAccessException>(() => _controller.TestGetUserId());
        Assert.Equal("User ID not found in token", exception.Message);
    }

    [Fact]
    public void GetUserId_WithNonNumericClaim_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        SetupUser(new Claim(ClaimTypes.NameIdentifier, "not-a-number"));

        // Act & Assert
        var exception = Assert.Throws<UnauthorizedAccessException>(() => _controller.TestGetUserId());
        Assert.Equal("User ID not found in token", exception.Message);
    }

    #endregion
}
