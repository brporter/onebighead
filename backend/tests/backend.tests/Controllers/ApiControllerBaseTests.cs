using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace OneBigHead.Server.Tests.Controllers;

// Concrete implementation to test abstract base class

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

    #region GetWorkspaceId Tests

    [Fact]
    public void GetWorkspaceId_WithValidClaim_ReturnsWorkspaceId()
    {
        // Arrange
        SetupUser(new Claim("workspace_id", "42"));

        // Act
        var result = _controller.TestGetWorkspaceId();

        // Assert
        Assert.Equal(42, result);
    }

    [Fact]
    public void GetWorkspaceId_WithMissingClaim_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        SetupUser(new Claim("other_claim", "value"));

        // Act & Assert
        var exception = Assert.Throws<UnauthorizedAccessException>(() => _controller.TestGetWorkspaceId());
        Assert.Equal("Workspace ID not found in token", exception.Message);
    }

    [Fact]
    public void GetWorkspaceId_WithEmptyClaim_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        SetupUser(new Claim("workspace_id", ""));

        // Act & Assert
        var exception = Assert.Throws<UnauthorizedAccessException>(() => _controller.TestGetWorkspaceId());
        Assert.Equal("Workspace ID not found in token", exception.Message);
    }

    [Fact]
    public void GetWorkspaceId_WithNonNumericClaim_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        SetupUser(new Claim("workspace_id", "not-a-number"));

        // Act & Assert
        var exception = Assert.Throws<UnauthorizedAccessException>(() => _controller.TestGetWorkspaceId());
        Assert.Equal("Workspace ID not found in token", exception.Message);
    }

    #endregion

    #region TryGetWorkspaceId Tests

    [Fact]
    public void TryGetWorkspaceId_WithValidClaim_ReturnsWorkspaceId()
    {
        // Arrange
        SetupUser(new Claim("workspace_id", "42"));

        // Act
        var result = _controller.TestTryGetWorkspaceId();

        // Assert
        Assert.Equal(42, result);
    }

    [Fact]
    public void TryGetWorkspaceId_WithMissingClaim_ReturnsNull()
    {
        // Arrange
        SetupUser(new Claim("other_claim", "value"));

        // Act
        var result = _controller.TestTryGetWorkspaceId();

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void TryGetWorkspaceId_WithEmptyClaim_ReturnsNull()
    {
        // Arrange
        SetupUser(new Claim("workspace_id", ""));

        // Act
        var result = _controller.TestTryGetWorkspaceId();

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void TryGetWorkspaceId_WithNonNumericClaim_ReturnsNull()
    {
        // Arrange
        SetupUser(new Claim("workspace_id", "not-a-number"));

        // Act
        var result = _controller.TestTryGetWorkspaceId();

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
