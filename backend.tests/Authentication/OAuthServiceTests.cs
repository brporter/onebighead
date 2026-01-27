using backend.Authentication;
using backend.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Moq.Protected;
using System.Net;

namespace backend.Tests.Authentication;

[Trait("Category", "Unit")]
public class OAuthServiceTests
{
    private readonly Mock<IHttpClientFactory> _mockHttpClientFactory;
    private readonly Mock<ILogger<OAuthService>> _mockLogger;
    private readonly AuthenticationSettings _settings;
    private readonly OAuthService _service;

    public OAuthServiceTests()
    {
        _mockHttpClientFactory = new Mock<IHttpClientFactory>();
        _mockLogger = new Mock<ILogger<OAuthService>>();

        _settings = new AuthenticationSettings
        {
            OAuth = new OAuthSettings
            {
                BaseUrl = "https://localhost",
                CallbackPath = "/api/auth/callback",
                PostLoginRedirectUrl = "/collections",
                PostLoginErrorUrl = "/error"
            },
            Providers = new OidcProviderSettings
            {
                Microsoft = new OidcProvider 
                { 
                    Enabled = true, 
                    ClientId = "ms-client-id", 
                    ClientSecret = "ms-client-secret", 
                    Authority = "https://login.microsoftonline.com/common/v2.0" 
                },
                Google = new OidcProvider 
                { 
                    Enabled = true, 
                    ClientId = "google-client-id", 
                    ClientSecret = "google-client-secret", 
                    Authority = "https://accounts.google.com" 
                },
                Apple = new OidcProvider 
                { 
                    Enabled = false, 
                    ClientId = "apple-client-id", 
                    ClientSecret = "apple-client-secret",
                    Authority = "https://appleid.apple.com"
                }
            }
        };

        var options = Options.Create(_settings);
        _service = new OAuthService(options, _mockHttpClientFactory.Object, _mockLogger.Object);
    }

    #region GenerateSecureState Tests

    [Fact]
    public void GenerateSecureState_ReturnsNonEmptyString()
    {
        // Act
        var state = _service.GenerateSecureState();

        // Assert
        Assert.False(string.IsNullOrEmpty(state));
    }

    [Fact]
    public void GenerateSecureState_ReturnsUniqueValues()
    {
        // Act
        var state1 = _service.GenerateSecureState();
        var state2 = _service.GenerateSecureState();

        // Assert
        Assert.NotEqual(state1, state2);
    }

    [Fact]
    public void GenerateSecureState_ReturnsUrlSafeString()
    {
        // Act
        var state = _service.GenerateSecureState();

        // Assert
        Assert.DoesNotContain("+", state);
        Assert.DoesNotContain("/", state);
        Assert.DoesNotContain("=", state);
    }

    #endregion

    #region ValidateState Tests

    [Fact]
    public void ValidateState_ReturnsTrue_WhenStatesMatch()
    {
        // Act
        var result = _service.ValidateState("state123", "state123");

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void ValidateState_ReturnsFalse_WhenStatesDontMatch()
    {
        // Act
        var result = _service.ValidateState("state123", "state456");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void ValidateState_ReturnsFalse_WhenStateIsEmpty()
    {
        // Act
        var result = _service.ValidateState("", "state123");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void ValidateState_ReturnsFalse_WhenStoredStateIsEmpty()
    {
        // Act
        var result = _service.ValidateState("state123", "");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void ValidateState_ReturnsFalse_WhenBothEmpty()
    {
        // Act
        var result = _service.ValidateState("", "");

        // Assert
        Assert.False(result);
    }

    #endregion

    #region GenerateAuthorizationUrl Tests

    [Fact]
    public void GenerateAuthorizationUrl_ReturnsValidGoogleUrl()
    {
        // Arrange
        var state = "test-state";

        // Act
        var url = _service.GenerateAuthorizationUrl(IdentityProvider.Google, state);

        // Assert
        Assert.Contains("accounts.google.com/o/oauth2/v2/auth", url);
        Assert.Contains("client_id=google-client-id", url);
        Assert.Contains("state=test-state", url);
        Assert.Contains("response_type=code", url);
        Assert.Contains("scope=openid", url);
    }

    [Fact]
    public void GenerateAuthorizationUrl_ReturnsValidMicrosoftUrl()
    {
        // Arrange
        var state = "test-state";

        // Act
        var url = _service.GenerateAuthorizationUrl(IdentityProvider.Microsoft, state);

        // Assert
        Assert.Contains("login.microsoftonline.com/common/oauth2/v2.0/authorize", url);
        Assert.Contains("client_id=ms-client-id", url);
        Assert.Contains("response_mode=query", url); // Microsoft-specific
    }

    [Fact]
    public void GenerateAuthorizationUrl_ThrowsForDisabledProvider()
    {
        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() => 
            _service.GenerateAuthorizationUrl(IdentityProvider.Apple, "state"));
        Assert.Contains("not enabled", ex.Message);
    }

    [Fact]
    public void GenerateAuthorizationUrl_IncludesNonce_WhenProvided()
    {
        // Act
        var url = _service.GenerateAuthorizationUrl(IdentityProvider.Google, "state", "nonce123");

        // Assert
        Assert.Contains("nonce=nonce123", url);
    }

    [Fact]
    public void GenerateAuthorizationUrl_IncludesCorrectRedirectUri()
    {
        // Act
        var url = _service.GenerateAuthorizationUrl(IdentityProvider.Google, "state");

        // Assert
        Assert.Contains("redirect_uri=https", url);
        Assert.Contains("callback", url);
        Assert.Contains("google", url);
    }

    [Fact]
    public void GenerateAuthorizationUrl_AppleUsesFormPost()
    {
        // Arrange - create a new service with Apple enabled
        var settings = new AuthenticationSettings
        {
            OAuth = new OAuthSettings
            {
                BaseUrl = "https://localhost",
                CallbackPath = "/api/auth/callback"
            },
            Providers = new OidcProviderSettings
            {
                Apple = new OidcProvider 
                { 
                    Enabled = true, 
                    ClientId = "apple-client-id", 
                    ClientSecret = "apple-secret",
                    Authority = "https://appleid.apple.com"
                },
                Microsoft = new OidcProvider { Enabled = false },
                Google = new OidcProvider { Enabled = false }
            }
        };
        var service = new OAuthService(Options.Create(settings), _mockHttpClientFactory.Object, _mockLogger.Object);

        // Act
        var url = service.GenerateAuthorizationUrl(IdentityProvider.Apple, "state");

        // Assert
        Assert.Contains("appleid.apple.com/auth/authorize", url);
        Assert.Contains("response_mode=form_post", url); // Apple-specific
    }

    #endregion

    #region ExchangeCodeForTokensAsync Tests

    [Fact]
    public async Task ExchangeCodeForTokensAsync_ReturnsSuccess_WhenResponseIsValid()
    {
        // Arrange
        var mockHandler = new Mock<HttpMessageHandler>();
        mockHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent("{\"id_token\":\"test-id-token\",\"access_token\":\"test-access-token\"}")
            });

        var httpClient = new HttpClient(mockHandler.Object);
        _mockHttpClientFactory.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        // Act
        var result = await _service.ExchangeCodeForTokensAsync("auth-code", IdentityProvider.Google);

        // Assert
        Assert.True(result.Success);
        Assert.Equal("test-id-token", result.IdToken);
        Assert.Equal("test-access-token", result.AccessToken);
    }

    [Fact]
    public async Task ExchangeCodeForTokensAsync_ReturnsError_WhenResponseFails()
    {
        // Arrange
        var mockHandler = new Mock<HttpMessageHandler>();
        mockHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.BadRequest,
                Content = new StringContent("{\"error\":\"invalid_grant\"}")
            });

        var httpClient = new HttpClient(mockHandler.Object);
        _mockHttpClientFactory.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        // Act
        var result = await _service.ExchangeCodeForTokensAsync("bad-code", IdentityProvider.Google);

        // Assert
        Assert.False(result.Success);
        Assert.Contains("Token exchange failed", result.Error);
    }

    [Fact]
    public async Task ExchangeCodeForTokensAsync_ReturnsError_WhenExceptionOccurs()
    {
        // Arrange
        var mockHandler = new Mock<HttpMessageHandler>();
        mockHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(new HttpRequestException("Network error"));

        var httpClient = new HttpClient(mockHandler.Object);
        _mockHttpClientFactory.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        // Act
        var result = await _service.ExchangeCodeForTokensAsync("code", IdentityProvider.Google);

        // Assert
        Assert.False(result.Success);
        Assert.Contains("error occurred", result.Error);
    }

    [Fact]
    public async Task ExchangeCodeForTokensAsync_IncludesRefreshToken_WhenProvided()
    {
        // Arrange
        var mockHandler = new Mock<HttpMessageHandler>();
        mockHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent("{\"id_token\":\"id\",\"access_token\":\"access\",\"refresh_token\":\"refresh\"}")
            });

        var httpClient = new HttpClient(mockHandler.Object);
        _mockHttpClientFactory.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        // Act
        var result = await _service.ExchangeCodeForTokensAsync("code", IdentityProvider.Google);

        // Assert
        Assert.True(result.Success);
        Assert.Equal("refresh", result.RefreshToken);
    }

    #endregion
}
