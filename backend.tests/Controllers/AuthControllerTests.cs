using backend.Authentication;
using backend.Controllers;
using backend.Data;
using backend.DTOs;
using backend.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using System.Security.Claims;

namespace backend.Tests.Controllers;

[Trait("Category", "Unit")]
public class AuthControllerTests
{
    private readonly Mock<IOidcTokenValidator> _mockTokenValidator;
    private readonly Mock<ITokenService> _mockTokenService;
    private readonly Mock<IUserRepository> _mockUserRepository;
    private readonly Mock<ITenantRepository> _mockTenantRepository;
    private readonly Mock<IOAuthService> _mockOAuthService;
    private readonly Mock<ILogger<AuthController>> _mockLogger;
    private readonly AuthenticationSettings _settings;
    private readonly AuthController _controller;

    public AuthControllerTests()
    {
        _mockTokenValidator = new Mock<IOidcTokenValidator>();
        _mockTokenService = new Mock<ITokenService>();
        _mockUserRepository = new Mock<IUserRepository>();
        _mockTenantRepository = new Mock<ITenantRepository>();
        _mockOAuthService = new Mock<IOAuthService>();
        _mockLogger = new Mock<ILogger<AuthController>>();

        _settings = new AuthenticationSettings
        {
            Jwt = new JwtSettings
            {
                SigningKey = "test-key-that-is-at-least-32-characters-long",
                Issuer = "test-issuer",
                Audience = "test-audience",
                SlidingExpirationMinutes = 60,
                AbsoluteExpirationDays = 7
            },
            Cookie = new CookieSettings
            {
                Name = "auth_token",
                Secure = true,
                SameSite = "Strict"
            },
            OAuth = new OAuthSettings
            {
                BaseUrl = "https://localhost",
                CallbackPath = "/api/auth/callback",
                PostLoginRedirectUrl = "/collections",
                PostLoginErrorUrl = "/error"
            },
            Providers = new OidcProviderSettings
            {
                Microsoft = new OidcProvider { Enabled = true, ClientId = "ms-client", ClientSecret = "ms-secret", Authority = "https://login.microsoftonline.com/common/v2.0" },
                Google = new OidcProvider { Enabled = true, ClientId = "google-client", ClientSecret = "google-secret", Authority = "https://accounts.google.com" },
                Apple = new OidcProvider { Enabled = false }
            }
        };

        var options = Options.Create(_settings);

        _controller = new AuthController(
            _mockTokenValidator.Object,
            _mockTokenService.Object,
            _mockUserRepository.Object,
            _mockTenantRepository.Object,
            _mockOAuthService.Object,
            options,
            _mockLogger.Object);

        SetupHttpContext();
    }

    private void SetupHttpContext(bool authenticated = false, int tenantId = 1, string email = "test@example.com")
    {
        var httpContext = new DefaultHttpContext();
        
        if (authenticated)
        {
            var claims = new List<Claim>
            {
                new("tenant_id", tenantId.ToString()),
                new(ClaimTypes.NameIdentifier, "1"),
                new(ClaimTypes.Email, email)
            };
            var identity = new ClaimsIdentity(claims, "TestAuth");
            httpContext.User = new ClaimsPrincipal(identity);
        }

        httpContext.Request.Scheme = "https";
        httpContext.Request.Host = new HostString("localhost");
        httpContext.Response.Body = new MemoryStream();

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };
    }

    #region Login Tests

    [Fact]
    public void Login_ReturnsBadRequest_WhenProviderIsInvalid()
    {
        // Act
        var result = _controller.Login("invalid-provider");

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("Invalid identity provider", badRequest.Value?.ToString());
    }

    [Fact]
    public void Login_RedirectsToAuthUrl_WhenProviderIsValid()
    {
        // Arrange
        _mockOAuthService.Setup(s => s.GenerateSecureState()).Returns("test-state");
        _mockOAuthService.Setup(s => s.GenerateAuthorizationUrl(IdentityProvider.Google, "test-state", null))
            .Returns("https://accounts.google.com/auth?state=test-state");

        // Act
        var result = _controller.Login("google");

        // Assert
        var redirectResult = Assert.IsType<RedirectResult>(result);
        Assert.Contains("accounts.google.com", redirectResult.Url);
    }

    [Fact]
    public void Login_SetsStateCookie()
    {
        // Arrange
        _mockOAuthService.Setup(s => s.GenerateSecureState()).Returns("test-state");
        _mockOAuthService.Setup(s => s.GenerateAuthorizationUrl(IdentityProvider.Microsoft, "test-state", null))
            .Returns("https://login.microsoftonline.com/auth");

        // Act
        _controller.Login("microsoft");

        // Assert
        Assert.True(_controller.Response.Headers.ContainsKey("Set-Cookie"));
    }

    [Fact]
    public void Login_RedirectsToError_WhenProviderDisabled()
    {
        // Arrange
        _mockOAuthService.Setup(s => s.GenerateSecureState()).Returns("test-state");
        _mockOAuthService.Setup(s => s.GenerateAuthorizationUrl(IdentityProvider.Apple, "test-state", null))
            .Throws(new InvalidOperationException("Provider Apple is not enabled"));

        // Act
        var result = _controller.Login("apple");

        // Assert
        var redirectResult = Assert.IsType<RedirectResult>(result);
        Assert.Contains("error", redirectResult.Url);
    }

    [Fact]
    public void Login_StoresReturnUrl_WhenProvided()
    {
        // Arrange
        _mockOAuthService.Setup(s => s.GenerateSecureState()).Returns("test-state");
        _mockOAuthService.Setup(s => s.GenerateAuthorizationUrl(IdentityProvider.Google, "test-state", null))
            .Returns("https://accounts.google.com/auth");

        // Act
        _controller.Login("google", returnUrl: "/dashboard");

        // Assert
        var cookies = _controller.Response.Headers["Set-Cookie"].ToString();
        Assert.Contains("oauth_return_url", cookies);
    }

    #endregion

    #region Callback Tests

    [Fact]
    public async Task CallbackGet_RedirectsToError_WhenOAuthError()
    {
        // Act
        var result = await _controller.CallbackGet("google", error: "access_denied", error_description: "User cancelled");

        // Assert
        var redirectResult = Assert.IsType<RedirectResult>(result);
        Assert.Contains("error", redirectResult.Url);
    }

    [Fact]
    public async Task CallbackGet_RedirectsToError_WhenProviderInvalid()
    {
        // Act
        var result = await _controller.CallbackGet("invalid");

        // Assert
        var redirectResult = Assert.IsType<RedirectResult>(result);
        Assert.Contains("error", redirectResult.Url);
    }

    [Fact]
    public async Task CallbackGet_RedirectsToError_WhenStateMismatch()
    {
        // Arrange
        _mockOAuthService.Setup(s => s.ValidateState("state1", "state2")).Returns(false);

        // Act
        var result = await _controller.CallbackGet("google", code: "auth-code", state: "state1");

        // Assert
        var redirectResult = Assert.IsType<RedirectResult>(result);
        Assert.Contains("error", redirectResult.Url);
    }

    [Fact]
    public async Task CallbackGet_RedirectsToError_WhenNoCode()
    {
        // Arrange
        _mockOAuthService.Setup(s => s.ValidateState("state", "state")).Returns(true);
        _controller.HttpContext.Request.Headers.Cookie = "oauth_state=state";

        // Act
        var result = await _controller.CallbackGet("google", state: "state");

        // Assert
        var redirectResult = Assert.IsType<RedirectResult>(result);
        Assert.Contains("error", redirectResult.Url);
    }

    [Fact]
    public async Task CallbackGet_RedirectsToError_WhenTokenExchangeFails()
    {
        // Arrange
        _mockOAuthService.Setup(s => s.ValidateState(It.IsAny<string>(), It.IsAny<string>())).Returns(true);
        _mockOAuthService.Setup(s => s.ExchangeCodeForTokensAsync("code", IdentityProvider.Google))
            .ReturnsAsync(new OAuthTokenResponse { Success = false, Error = "Token exchange failed" });

        // Act
        var result = await _controller.CallbackGet("google", code: "code", state: "state");

        // Assert
        var redirectResult = Assert.IsType<RedirectResult>(result);
        Assert.Contains("error", redirectResult.Url);
    }

    [Fact]
    public async Task CallbackGet_RedirectsToError_WhenTokenValidationFails()
    {
        // Arrange
        _mockOAuthService.Setup(s => s.ValidateState(It.IsAny<string>(), It.IsAny<string>())).Returns(true);
        _mockOAuthService.Setup(s => s.ExchangeCodeForTokensAsync("code", IdentityProvider.Google))
            .ReturnsAsync(new OAuthTokenResponse { Success = true, IdToken = "id-token" });
        _mockTokenValidator.Setup(v => v.ValidateTokenAsync("id-token", IdentityProvider.Google))
            .ReturnsAsync(new OidcValidationResult { IsValid = false, Error = "Invalid token" });

        // Act
        var result = await _controller.CallbackGet("google", code: "code", state: "state");

        // Assert
        var redirectResult = Assert.IsType<RedirectResult>(result);
        Assert.Contains("error", redirectResult.Url);
    }

    [Fact]
    public async Task CallbackGet_RedirectsToApp_WhenSuccessful()
    {
        // Arrange
        var user = new User { Id = 1, TenantId = 1, Email = "test@example.com" };

        _mockOAuthService.Setup(s => s.ValidateState(It.IsAny<string>(), It.IsAny<string>())).Returns(true);
        _mockOAuthService.Setup(s => s.ExchangeCodeForTokensAsync("code", IdentityProvider.Google))
            .ReturnsAsync(new OAuthTokenResponse { Success = true, IdToken = "id-token" });
        _mockTokenValidator.Setup(v => v.ValidateTokenAsync("id-token", IdentityProvider.Google))
            .ReturnsAsync(new OidcValidationResult { IsValid = true, Email = "test@example.com", Subject = "sub123" });
        _mockUserRepository.Setup(r => r.GetByProviderIdAsync(IdentityProvider.Google, "sub123"))
            .ReturnsAsync(user);
        _mockTokenService.Setup(t => t.GenerateAppToken(user)).Returns("app-token");

        // Act
        var result = await _controller.CallbackGet("google", code: "code", state: "state");

        // Assert
        var redirectResult = Assert.IsType<RedirectResult>(result);
        Assert.Equal("/collections", redirectResult.Url);
    }

    [Fact]
    public async Task CallbackGet_CreatesNewUser_WhenNotFound()
    {
        // Arrange
        var newUser = new User { Id = 1, TenantId = 1, Email = "new@example.com" };

        _mockOAuthService.Setup(s => s.ValidateState(It.IsAny<string>(), It.IsAny<string>())).Returns(true);
        _mockOAuthService.Setup(s => s.ExchangeCodeForTokensAsync("code", IdentityProvider.Google))
            .ReturnsAsync(new OAuthTokenResponse { Success = true, IdToken = "id-token" });
        _mockTokenValidator.Setup(v => v.ValidateTokenAsync("id-token", IdentityProvider.Google))
            .ReturnsAsync(new OidcValidationResult { IsValid = true, Email = "new@example.com", Subject = "sub123" });
        _mockUserRepository.Setup(r => r.GetByProviderIdAsync(IdentityProvider.Google, "sub123"))
            .ReturnsAsync((User?)null);
        _mockUserRepository.Setup(r => r.GetByEmailAsync("new@example.com"))
            .ReturnsAsync((User?)null);
        _mockUserRepository.Setup(r => r.CreateWithNewTenantAsync("new@example.com", IdentityProvider.Google, "sub123"))
            .ReturnsAsync(newUser);
        _mockTokenService.Setup(t => t.GenerateAppToken(newUser)).Returns("app-token");

        // Act
        var result = await _controller.CallbackGet("google", code: "code", state: "state");

        // Assert
        _mockUserRepository.Verify(r => r.CreateWithNewTenantAsync("new@example.com", IdentityProvider.Google, "sub123"), Times.Once);
    }

    [Fact]
    public async Task CallbackPost_HandlesAppleCallback()
    {
        // Arrange
        _mockOAuthService.Setup(s => s.ValidateState(It.IsAny<string>(), It.IsAny<string>())).Returns(false);

        // Act - Apple uses POST callbacks
        var result = await _controller.CallbackPost("apple", code: "code", state: "state");

        // Assert
        var redirectResult = Assert.IsType<RedirectResult>(result);
        Assert.Contains("error", redirectResult.Url);
    }

    #endregion

    #region Callback (JSON) Tests

    [Fact]
    public async Task Callback_ReturnsBadRequest_WhenTokenMissing()
    {
        // Arrange
        var request = new AuthCallbackRequest { Token = "", Provider = "google" };

        // Act
        var result = await _controller.Callback(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Callback_ReturnsBadRequest_WhenProviderInvalid()
    {
        // Arrange
        var request = new AuthCallbackRequest { Token = "token", Provider = "invalid" };

        // Act
        var result = await _controller.Callback(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Callback_ReturnsUnauthorized_WhenTokenInvalid()
    {
        // Arrange
        var request = new AuthCallbackRequest { Token = "invalid-token", Provider = "google" };
        _mockTokenValidator.Setup(v => v.ValidateTokenAsync("invalid-token", IdentityProvider.Google))
            .ReturnsAsync(new OidcValidationResult { IsValid = false, Error = "Invalid token" });

        // Act
        var result = await _controller.Callback(request);

        // Assert
        Assert.IsType<UnauthorizedObjectResult>(result);
    }

    [Fact]
    public async Task Callback_ReturnsOk_WhenSuccessful()
    {
        // Arrange
        var request = new AuthCallbackRequest { Token = "valid-token", Provider = "google" };
        var user = new User { Id = 1, TenantId = 1, Email = "test@example.com", Tenant = new Tenant { Name = "Test Tenant" } };

        _mockTokenValidator.Setup(v => v.ValidateTokenAsync("valid-token", IdentityProvider.Google))
            .ReturnsAsync(new OidcValidationResult { IsValid = true, Email = "test@example.com", Subject = "sub123" });
        _mockUserRepository.Setup(r => r.GetByProviderIdAsync(IdentityProvider.Google, "sub123"))
            .ReturnsAsync(user);
        _mockTokenService.Setup(t => t.GenerateAppToken(user)).Returns("app-token");

        // Act
        var result = await _controller.Callback(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AuthCallbackResponse>(okResult.Value);
        Assert.True(response.Success);
        Assert.Equal("test@example.com", response.Email);
    }

    #endregion

    #region Logout Tests

    [Fact]
    public void Logout_ReturnsOk_AndDeletesCookie()
    {
        // Act
        var result = _controller.Logout();

        // Assert
        Assert.IsType<OkObjectResult>(result);
    }

    #endregion

    #region GetCurrentUser Tests

    [Fact]
    public async Task GetCurrentUser_ReturnsUnauthorized_WhenNotAuthenticated()
    {
        // Arrange - default setup has no auth

        // Act
        var result = await _controller.GetCurrentUser();

        // Assert
        Assert.IsType<UnauthorizedObjectResult>(result);
    }

    [Fact]
    public async Task GetCurrentUser_ReturnsUser_WhenAuthenticated()
    {
        // Arrange
        SetupHttpContext(authenticated: true, tenantId: 5, email: "user@test.com");
        _mockTenantRepository.Setup(r => r.GetByIdAsync(5))
            .ReturnsAsync(new Tenant { Id = 5, Name = "Test Tenant", HasCompletedWelcome = true });

        // Act
        var result = await _controller.GetCurrentUser();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        Assert.NotNull(okResult.Value);
    }

    [Fact]
    public async Task GetCurrentUser_ReturnsHasCompletedWelcome_FromTenant()
    {
        // Arrange
        SetupHttpContext(authenticated: true, tenantId: 1, email: "user@test.com");
        _mockTenantRepository.Setup(r => r.GetByIdAsync(1))
            .ReturnsAsync(new Tenant { Id = 1, Name = "Test", HasCompletedWelcome = false });

        // Act
        var result = await _controller.GetCurrentUser();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var json = System.Text.Json.JsonSerializer.Serialize(okResult.Value);
        Assert.Contains("\"hasCompletedWelcome\":false", json);
    }

    #endregion

    #region CompleteWelcome Tests

    [Fact]
    public async Task CompleteWelcome_ReturnsUnauthorized_WhenNotAuthenticated()
    {
        // Arrange - default setup has no auth
        var request = new backend.DTOs.CompleteWelcomeRequest { TenantName = "Test" };

        // Act
        var result = await _controller.CompleteWelcome(request);

        // Assert
        Assert.IsType<UnauthorizedObjectResult>(result);
    }

    [Fact]
    public async Task CompleteWelcome_UpdatesTenantName_WhenProvided()
    {
        // Arrange
        SetupHttpContext(authenticated: true, tenantId: 1, email: "user@test.com");
        var tenant = new Tenant { Id = 1, Name = "Old Name", HasCompletedWelcome = false };
        _mockTenantRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(tenant);
        var request = new backend.DTOs.CompleteWelcomeRequest { TenantName = "New Name" };

        // Act
        var result = await _controller.CompleteWelcome(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        Assert.Equal("New Name", tenant.Name);
        Assert.True(tenant.HasCompletedWelcome);
        _mockTenantRepository.Verify(r => r.UpdateAsync(tenant), Times.Once);
    }

    [Fact]
    public async Task CompleteWelcome_UsesEmail_WhenTenantNameNotProvided()
    {
        // Arrange
        SetupHttpContext(authenticated: true, tenantId: 1, email: "user@example.com");
        var tenant = new Tenant { Id = 1, Name = "Old Name", HasCompletedWelcome = false };
        _mockTenantRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(tenant);
        var request = new backend.DTOs.CompleteWelcomeRequest { TenantName = null };

        // Act
        var result = await _controller.CompleteWelcome(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        Assert.Equal("user@example.com", tenant.Name);
        Assert.True(tenant.HasCompletedWelcome);
    }

    [Fact]
    public async Task CompleteWelcome_SetsHasCompletedWelcome_ToTrue()
    {
        // Arrange
        SetupHttpContext(authenticated: true, tenantId: 1, email: "user@test.com");
        var tenant = new Tenant { Id = 1, Name = "Test", HasCompletedWelcome = false };
        _mockTenantRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(tenant);
        var request = new backend.DTOs.CompleteWelcomeRequest { TenantName = "My Org" };

        // Act
        await _controller.CompleteWelcome(request);

        // Assert
        Assert.True(tenant.HasCompletedWelcome);
    }

    [Fact]
    public async Task CompleteWelcome_ReturnsNotFound_WhenTenantDoesNotExist()
    {
        // Arrange
        SetupHttpContext(authenticated: true, tenantId: 999, email: "user@test.com");
        _mockTenantRepository.Setup(r => r.GetByIdAsync(999)).ReturnsAsync((Tenant?)null);
        var request = new backend.DTOs.CompleteWelcomeRequest { TenantName = "Test" };

        // Act
        var result = await _controller.CompleteWelcome(request);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    #endregion
}
