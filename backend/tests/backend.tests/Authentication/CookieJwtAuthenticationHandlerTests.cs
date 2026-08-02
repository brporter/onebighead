using System.Text.Encodings.Web;
using System.Text.Json;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;

namespace OneBigHead.Server.Tests.Authentication;

[Trait("Category", "Unit")]
public class CookieJwtAuthenticationHandlerTests
{
    private const int TestUserId = 7;

    private readonly AuthenticationSettings _settings;
    private readonly TokenService _tokenService;
    private readonly Mock<ITokenRevocationService> _mockRevocationService;

    public CookieJwtAuthenticationHandlerTests()
    {
        _settings = new AuthenticationSettings
        {
            Jwt = new JwtSettings
            {
                SigningKey = "ThisIsATestSigningKeyThatIsLongEnough123456",
                Issuer = "test-issuer",
                Audience = "test-audience",
                SlidingExpirationMinutes = 60
            }
        };

        _tokenService = new TokenService(Options.Create(_settings));
        _mockRevocationService = new Mock<ITokenRevocationService>();
    }

    private async Task<(CookieJwtAuthenticationHandler handler, DefaultHttpContext context)> CreateHandlerAsync(
        string? cookieToken)
    {
        var options = new Mock<IOptionsMonitor<CookieJwtAuthenticationOptions>>();
        options.Setup(o => o.Get(It.IsAny<string>())).Returns(new CookieJwtAuthenticationOptions());

        var handler = new CookieJwtAuthenticationHandler(
            options.Object,
            NullLoggerFactory.Instance,
            UrlEncoder.Default,
            _tokenService,
            _mockRevocationService.Object,
            Options.Create(_settings));

        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();

        if (cookieToken != null)
        {
            context.Request.Headers.Cookie = $"{_settings.Cookie.Name}={cookieToken}";
        }

        var scheme = new AuthenticationScheme(
            CookieJwtAuthenticationExtensions.SchemeName,
            null,
            typeof(CookieJwtAuthenticationHandler));

        await handler.InitializeAsync(scheme, context);
        return (handler, context);
    }

    private string GenerateToken(int expirationMinutes = 60)
    {
        var user = new User
        {
            Id = TestUserId,
            ActiveWorkspaceId = 1,
            Email = "test@example.com",
            IdentityProvider = IdentityProvider.Microsoft
        };

        var settings = new AuthenticationSettings
        {
            Jwt = new JwtSettings
            {
                SigningKey = _settings.Jwt.SigningKey,
                Issuer = _settings.Jwt.Issuer,
                Audience = _settings.Jwt.Audience,
                SlidingExpirationMinutes = expirationMinutes
            }
        };

        return new TokenService(Options.Create(settings)).GenerateAppToken(user, WorkspaceRole.Normal);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_NoCookie_ReturnsNoResultWithoutRevocationLookup()
    {
        var (handler, _) = await CreateHandlerAsync(cookieToken: null);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.True(result.None);
        _mockRevocationService.Verify(
            s => s.IsTokenRevokedAsync(It.IsAny<int>(), It.IsAny<DateTime>()), Times.Never);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_GarbageToken_FailsWithoutRevocationLookup()
    {
        var (handler, _) = await CreateHandlerAsync("not-a-real-token");

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        _mockRevocationService.Verify(
            s => s.IsTokenRevokedAsync(It.IsAny<int>(), It.IsAny<DateTime>()), Times.Never);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ExpiredToken_FailsWithoutRevocationLookup()
    {
        // Expired beyond the 5-minute clock skew allowance
        var expiredToken = GenerateToken(expirationMinutes: -10);
        var (handler, _) = await CreateHandlerAsync(expiredToken);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        _mockRevocationService.Verify(
            s => s.IsTokenRevokedAsync(It.IsAny<int>(), It.IsAny<DateTime>()), Times.Never);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ValidTokenNotRevoked_Succeeds()
    {
        _mockRevocationService.Setup(s => s.IsTokenRevokedAsync(TestUserId, It.IsAny<DateTime>()))
            .ReturnsAsync(false);
        var (handler, _) = await CreateHandlerAsync(GenerateToken());

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Principal);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ValidToken_ChecksRevocationWithTokenIssuedAt()
    {
        _mockRevocationService.Setup(s => s.IsTokenRevokedAsync(TestUserId, It.IsAny<DateTime>()))
            .ReturnsAsync(false);
        var beforeIssue = DateTime.UtcNow.AddSeconds(-2);
        var (handler, _) = await CreateHandlerAsync(GenerateToken());
        var afterIssue = DateTime.UtcNow.AddSeconds(2);

        await handler.AuthenticateAsync();

        _mockRevocationService.Verify(s => s.IsTokenRevokedAsync(TestUserId, It.Is<DateTime>(
            iat => iat >= beforeIssue && iat <= afterIssue)), Times.Once);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_RevokedToken_FailsAndFlagsSessionRevoked()
    {
        _mockRevocationService.Setup(s => s.IsTokenRevokedAsync(TestUserId, It.IsAny<DateTime>()))
            .ReturnsAsync(true);
        var (handler, context) = await CreateHandlerAsync(GenerateToken());

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal(AuthErrorType.SessionRevoked,
            context.Items[CookieJwtAuthenticationHandler.AuthErrorItemKey]);
    }

    [Fact]
    public async Task HandleChallengeAsync_RevokedSession_Writes401WithErrorCode()
    {
        _mockRevocationService.Setup(s => s.IsTokenRevokedAsync(TestUserId, It.IsAny<DateTime>()))
            .ReturnsAsync(true);
        var (handler, context) = await CreateHandlerAsync(GenerateToken());

        await handler.AuthenticateAsync();
        await handler.ChallengeAsync(null);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);

        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body);
        var body = await reader.ReadToEndAsync();
        using var json = JsonDocument.Parse(body);
        Assert.Equal(nameof(AuthErrorType.SessionRevoked), json.RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public async Task HandleChallengeAsync_NoErrorType_Writes401WithEmptyBody()
    {
        var (handler, context) = await CreateHandlerAsync("not-a-real-token");

        await handler.AuthenticateAsync();
        await handler.ChallengeAsync(null);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Equal(0, context.Response.Body.Length);
    }
}
