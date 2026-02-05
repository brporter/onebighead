using OneBigHead.Server.Authentication;
using OneBigHead.Server.Models;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace OneBigHead.Server.Tests.Authentication;

[Trait("Category", "Unit")]
public class TokenServiceTests
{
    private readonly TokenService _tokenService;

    public TokenServiceTests()
    {
        var settings = new AuthenticationSettings
        {
            Jwt = new JwtSettings
            {
                SigningKey = "ThisIsATestSigningKeyThatIsLongEnough123456",
                Issuer = "test-issuer",
                Audience = "test-audience",
                SlidingExpirationMinutes = 60,
                AbsoluteExpirationDays = 7
            }
        };

        _tokenService = new TokenService(Options.Create(settings));
    }

    [Fact]
    public void GenerateAppToken_ReturnsValidJwt()
    {
        // Arrange
        var user = new User
        {
            Id = 1,
            ActiveWorkspaceId = 42,
            Email = "test@example.com",
            IdentityProvider = IdentityProvider.Microsoft,
            ProviderSubjectId = "provider-sub-123"
        };

        // Act
        var token = _tokenService.GenerateAppToken(user, WorkspaceRole.Normal);

        // Assert
        Assert.NotNull(token);
        Assert.NotEmpty(token);
        Assert.Contains(".", token); // JWT format has dots
    }

    [Fact]
    public void ValidateAppToken_ReturnsClaimsPrincipal_ForValidToken()
    {
        // Arrange
        var user = new User
        {
            Id = 1,
            ActiveWorkspaceId = 42,
            Email = "test@example.com",
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "google-sub-456"
        };
        var token = _tokenService.GenerateAppToken(user, WorkspaceRole.Normal);

        // Act
        var principal = _tokenService.ValidateAppToken(token);

        // Assert
        Assert.NotNull(principal);

        var workspaceIdClaim = principal.FindFirst("workspace_id")?.Value;
        Assert.Equal("42", workspaceIdClaim);

        var emailClaim = principal.FindFirst(ClaimTypes.Email)?.Value;
        Assert.Equal("test@example.com", emailClaim);

        var userIdClaim = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        Assert.Equal("1", userIdClaim);
    }

    [Fact]
    public void ValidateAppToken_ReturnsNull_ForInvalidToken()
    {
        // Act
        var principal = _tokenService.ValidateAppToken("invalid-token");

        // Assert
        Assert.Null(principal);
    }

    [Fact]
    public void ValidateAppToken_ReturnsNull_ForTamperedToken()
    {
        // Arrange
        var user = new User
        {
            Id = 1,
            ActiveWorkspaceId = 42,
            Email = "test@example.com",
            IdentityProvider = IdentityProvider.Apple,
            ProviderSubjectId = "apple-sub-789"
        };
        var token = _tokenService.GenerateAppToken(user, WorkspaceRole.Normal);
        var tamperedToken = token + "tampered";

        // Act
        var principal = _tokenService.ValidateAppToken(tamperedToken);

        // Assert
        Assert.Null(principal);
    }

    [Fact]
    public void GenerateAppToken_IncludesProviderClaim()
    {
        // Arrange
        var user = new User
        {
            Id = 1,
            ActiveWorkspaceId = 42,
            Email = "test@example.com",
            IdentityProvider = IdentityProvider.Microsoft,
            ProviderSubjectId = "ms-sub-123"
        };

        // Act
        var token = _tokenService.GenerateAppToken(user, WorkspaceRole.Normal);
        var principal = _tokenService.ValidateAppToken(token);

        // Assert
        Assert.NotNull(principal);
        var providerClaim = principal.FindFirst("provider")?.Value;
        Assert.Equal("Microsoft", providerClaim);
    }
}

