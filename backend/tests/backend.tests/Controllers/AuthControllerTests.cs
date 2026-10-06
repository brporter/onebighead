using OneBigHead.Server.Authentication;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using System.Security.Claims;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class AuthControllerTests
{
    private readonly Mock<IOidcTokenValidator> _mockTokenValidator;
    private readonly Mock<ITokenService> _mockTokenService;
    private readonly Mock<IUserRepository> _mockUserRepository;
    private readonly Mock<IWorkspaceRepository> _mockWorkspaceRepository;
    private readonly Mock<IWorkspaceUserRepository> _mockWorkspaceUserRepository;
    private readonly Mock<ILogger<AuthController>> _mockLogger;
    private readonly AuthenticationSettings _settings;
    private readonly AuthController _controller;

    public AuthControllerTests()
    {
        _mockTokenValidator = new Mock<IOidcTokenValidator>();
        _mockTokenService = new Mock<ITokenService>();
        _mockUserRepository = new Mock<IUserRepository>();
        _mockWorkspaceRepository = new Mock<IWorkspaceRepository>();
        _mockWorkspaceUserRepository = new Mock<IWorkspaceUserRepository>();
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
            _mockWorkspaceRepository.Object,
            _mockWorkspaceUserRepository.Object,
            new ExternalUserService(_mockUserRepository.Object, _mockWorkspaceUserRepository.Object, Microsoft.Extensions.Logging.Abstractions.NullLogger<ExternalUserService>.Instance),
            options,
            _mockLogger.Object);

        SetupHttpContext();
        var url = new Mock<IUrlHelper>();
        url.Setup(u => u.IsLocalUrl(It.IsAny<string>())).Returns((string value) => value.StartsWith("/") && !value.StartsWith("//"));
        _controller.Url = url.Object;
    }

    private void SetupHttpContext(bool authenticated = false, int workspaceId = 1, string email = "test@example.com")
    {
        var httpContext = new DefaultHttpContext();
        
        if (authenticated)
        {
            var claims = new List<Claim>
            {
                new("workspace_id", workspaceId.ToString()),
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

    [Theory]
    [InlineData("invalid")]
    [InlineData("None")]
    [InlineData("99")]
    public void Login_RejectsUnsupportedProvider(string provider) => Assert.IsType<BadRequestObjectResult>(_controller.Login(provider));

    [Theory]
    [InlineData("google", "Google")]
    [InlineData("MICROSOFT", "Microsoft")]
    public void Login_ChallengesNamedProvider(string provider, string scheme)
    {
        var result = Assert.IsType<ChallengeResult>(_controller.Login(provider, "/collections/42"));
        Assert.Equal(scheme, Assert.Single(result.AuthenticationSchemes));
        Assert.Equal("/collections/42", result.Properties!.RedirectUri);
    }

    [Fact]
    public void Login_UsesDefaultReturnUrlForExternalUrl()
    {
        var result = Assert.IsType<ChallengeResult>(_controller.Login("google", "https://other.example"));
        Assert.Equal("/collections", result.Properties!.RedirectUri);
    }

    [Fact]
    public void Login_ReportsDisabledProvider() => Assert.Contains("not%20enabled", Assert.IsType<RedirectResult>(_controller.Login("apple")).Url);

    [Fact]
    public void UnavailableCallback_ReportsError() => Assert.StartsWith("/error?error=", Assert.IsType<RedirectResult>(_controller.UnavailableCallback()).Url);

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
        var user = new User { Id = 1, ActiveWorkspaceId = 1, Email = "test@example.com", ActiveWorkspace = new Workspace { Name = "Test Workspace" } };
        var membership = new WorkspaceUser { UserId = 1, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.Normal };

        _mockTokenValidator.Setup(v => v.ValidateTokenAsync("valid-token", IdentityProvider.Google))
            .ReturnsAsync(new OidcValidationResult { IsValid = true, Email = "test@example.com", Subject = "sub123" });
        _mockUserRepository.Setup(r => r.GetByProviderIdAsync(IdentityProvider.Google, "sub123"))
            .ReturnsAsync(user);
        _mockWorkspaceUserRepository.Setup(r => r.GetMembershipAsync(1, 1))
            .ReturnsAsync(membership);
        _mockTokenService.Setup(t => t.GenerateAppToken(user, WorkspaceRole.Normal)).Returns("app-token");

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
        SetupHttpContext(authenticated: true, workspaceId: 5, email: "user@test.com");
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(5))
            .ReturnsAsync(new Workspace { Id = 5, Name = "Test Workspace", HasCompletedWelcome = true });

        // Act
        var result = await _controller.GetCurrentUser();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        Assert.NotNull(okResult.Value);
    }

    [Fact]
    public async Task GetCurrentUser_ReturnsHasCompletedWelcome_FromWorkspace()
    {
        // Arrange
        SetupHttpContext(authenticated: true, workspaceId: 1, email: "user@test.com");
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1))
            .ReturnsAsync(new Workspace { Id = 1, Name = "Test", HasCompletedWelcome = false });

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
        var request = new OneBigHead.Server.DTOs.CompleteWelcomeRequest { WorkspaceName = "Test" };

        // Act
        var result = await _controller.CompleteWelcome(request);

        // Assert
        Assert.IsType<UnauthorizedObjectResult>(result);
    }

    [Fact]
    public async Task CompleteWelcome_UpdatesWorkspaceName_WhenProvided()
    {
        // Arrange
        SetupHttpContext(authenticated: true, workspaceId: 1, email: "user@test.com");
        var workspace = new Workspace { Id = 1, Name = "Old Name", HasCompletedWelcome = false };
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        var request = new OneBigHead.Server.DTOs.CompleteWelcomeRequest { WorkspaceName = "New Name" };

        // Act
        var result = await _controller.CompleteWelcome(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        Assert.Equal("New Name", workspace.Name);
        Assert.True(workspace.HasCompletedWelcome);
        _mockWorkspaceRepository.Verify(r => r.UpdateAsync(workspace), Times.Once);
    }

    [Fact]
    public async Task CompleteWelcome_UsesEmail_WhenWorkspaceNameNotProvided()
    {
        // Arrange
        SetupHttpContext(authenticated: true, workspaceId: 1, email: "user@example.com");
        var workspace = new Workspace { Id = 1, Name = "Old Name", HasCompletedWelcome = false };
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        var request = new OneBigHead.Server.DTOs.CompleteWelcomeRequest { WorkspaceName = null };

        // Act
        var result = await _controller.CompleteWelcome(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        Assert.Equal("user@example.com", workspace.Name);
        Assert.True(workspace.HasCompletedWelcome);
    }

    [Fact]
    public async Task CompleteWelcome_SetsHasCompletedWelcome_ToTrue()
    {
        // Arrange
        SetupHttpContext(authenticated: true, workspaceId: 1, email: "user@test.com");
        var workspace = new Workspace { Id = 1, Name = "Test", HasCompletedWelcome = false };
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        var request = new OneBigHead.Server.DTOs.CompleteWelcomeRequest { WorkspaceName = "My Org" };

        // Act
        await _controller.CompleteWelcome(request);

        // Assert
        Assert.True(workspace.HasCompletedWelcome);
    }

    [Fact]
    public async Task CompleteWelcome_ReturnsNotFound_WhenWorkspaceDoesNotExist()
    {
        // Arrange
        SetupHttpContext(authenticated: true, workspaceId: 999, email: "user@test.com");
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(999)).ReturnsAsync((Workspace?)null);
        var request = new OneBigHead.Server.DTOs.CompleteWelcomeRequest { WorkspaceName = "Test" };

        // Act
        var result = await _controller.CompleteWelcome(request);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    #endregion
}
