using System.Text.Encodings.Web;
using System.Text.Json;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
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
    private static readonly Guid TestStamp = Guid.NewGuid();

    private readonly AuthenticationSettings _settings;
    private readonly TokenService _tokenService;
    private readonly Mock<IAccountSessionValidator> _sessions;

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
        _sessions = new Mock<IAccountSessionValidator>();
    }

    private async Task<(CookieJwtAuthenticationHandler handler, DefaultHttpContext context)> CreateHandlerAsync(
        string? cookieToken, ITokenService? tokenService = null)
    {
        var options = new Mock<IOptionsMonitor<CookieJwtAuthenticationOptions>>();
        options.Setup(o => o.Get(It.IsAny<string>())).Returns(new CookieJwtAuthenticationOptions());

        var handler = new CookieJwtAuthenticationHandler(
            options.Object,
            NullLoggerFactory.Instance,
            UrlEncoder.Default,
            tokenService ?? _tokenService,
            _sessions.Object,
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
            AuthenticationStamp = TestStamp,
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
        _sessions.Verify(
            s => s.IsCurrentAsync(It.IsAny<int>(), It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_GarbageToken_FailsWithoutRevocationLookup()
    {
        var (handler, _) = await CreateHandlerAsync("not-a-real-token");

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        _sessions.Verify(
            s => s.IsCurrentAsync(It.IsAny<int>(), It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ExpiredToken_FailsWithoutRevocationLookup()
    {
        // Expired beyond the 5-minute clock skew allowance
        var expiredToken = GenerateToken(expirationMinutes: -10);
        var (handler, _) = await CreateHandlerAsync(expiredToken);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        _sessions.Verify(
            s => s.IsCurrentAsync(It.IsAny<int>(), It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ValidTokenNotRevoked_Succeeds()
    {
        _sessions.Setup(s => s.IsCurrentAsync(TestUserId, It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        var (handler, _) = await CreateHandlerAsync(GenerateToken());

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Principal);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ChecksExactAccountStampAndForwardsCancellation()
    {
        _sessions.Setup(s => s.IsCurrentAsync(TestUserId, TestStamp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        var (handler, context) = await CreateHandlerAsync(GenerateToken());
        using var cancellation = new CancellationTokenSource();
        context.RequestAborted = cancellation.Token;
        Assert.True((await handler.AuthenticateAsync()).Succeeded);
        _sessions.Verify(s => s.IsCurrentAsync(TestUserId, TestStamp, cancellation.Token), Times.Once);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_RevokedToken_FailsAndFlagsSessionRevoked()
    {
        _sessions.Setup(s => s.IsCurrentAsync(TestUserId, It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);
        var (handler, context) = await CreateHandlerAsync(GenerateToken());

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal(AuthErrorType.SessionRevoked,
            context.Items[CookieJwtAuthenticationHandler.AuthErrorItemKey]);
    }

    [Fact]
    public async Task HandleChallengeAsync_RevokedSession_Writes401WithErrorCode()
    {
        _sessions.Setup(s => s.IsCurrentAsync(TestUserId, It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);
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

    [Theory]
    [InlineData(null, "1700000000")]
    [InlineData("not-a-user", "1700000000")]
    [InlineData("2147483648", "1700000000")]
    [InlineData("0", "1700000000")]
    [InlineData("-7", "1700000000")]
    [InlineData("7", null)]
    [InlineData("7", "not-a-time")]
    [InlineData("7", "9223372036854775808")]
    [InlineData("7", "-62135596801")]
    [InlineData("7", "253402300800")]
    [InlineData("7", "9223372036854775807")]
    [InlineData("7", "-9223372036854775808")]
    public async Task MalformedIdentityOrIssuedAt_IsRejectedWithoutDatabaseLookup(string? userId, string? issuedAt)
    {
        var claims = new List<Claim>();
        if (userId != null) claims.Add(new Claim(ClaimTypes.NameIdentifier, userId));
        if (issuedAt != null) claims.Add(new Claim(JwtRegisteredClaimNames.Iat, issuedAt));
        var tokens = new Mock<ITokenService>(MockBehavior.Strict);
        tokens.Setup(t => t.ValidateAppToken("signed-token")).Returns(new ClaimsPrincipal(new ClaimsIdentity(claims, "Test")));
        var (handler, context) = await CreateHandlerAsync("signed-token", tokens.Object);
        var result = await handler.AuthenticateAsync();
        Assert.False(result.Succeeded);
        Assert.Equal("Invalid token claims", result.Failure!.Message);
        _sessions.VerifyNoOtherCalls();
        await handler.ChallengeAsync(null);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Equal(0, context.Response.Body.Length);
    }

    [Theory]
    [InlineData(-62135596800)]
    [InlineData(253402300799)]
    public async Task ValidIssuedAtBounds_DoNotDetermineSessionValidity(long issuedAt)
    {
        var tokens = new Mock<ITokenService>();
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, "7"), new Claim(JwtRegisteredClaimNames.Iat, issuedAt.ToString()),
            new Claim(ClaimNames.AuthenticationStamp, TestStamp.ToString("N"))
        }, "Test"));
        tokens.Setup(t => t.ValidateAppToken("signed-token")).Returns(principal);
        _sessions.Setup(s => s.IsCurrentAsync(7, TestStamp, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        var (handler, _) = await CreateHandlerAsync("signed-token", tokens.Object);
        var result = await handler.AuthenticateAsync();
        Assert.True(result.Succeeded);
        Assert.Same(principal, result.Principal);
        _sessions.Verify(r => r.IsCurrentAsync(7, TestStamp, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not-a-stamp")]
    [InlineData("00000000000000000000000000000000")]
    public async Task MissingOrInvalidStamp_RequiresSignInWithoutDatabaseLookup(string? stamp)
    {
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, "7"), new(JwtRegisteredClaimNames.Iat, "1700000000") };
        if (stamp is not null) claims.Add(new(ClaimNames.AuthenticationStamp, stamp));
        var tokens = new Mock<ITokenService>();
        tokens.Setup(t => t.ValidateAppToken("signed-token")).Returns(new ClaimsPrincipal(new ClaimsIdentity(claims, "Test")));
        var (handler, context) = await CreateHandlerAsync("signed-token", tokens.Object);
        Assert.False((await handler.AuthenticateAsync()).Succeeded);
        Assert.Equal(AuthErrorType.SessionRevoked, context.Items[CookieJwtAuthenticationHandler.AuthErrorItemKey]);
        _sessions.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("unrecognized")]
    [InlineData(AuthErrorType.None)]
    public async Task NonErrorChallengeMetadata_DoesNotExposeAnErrorPayload(object? metadata)
    {
        var (handler, context) = await CreateHandlerAsync(null);
        context.Items[CookieJwtAuthenticationHandler.AuthErrorItemKey] = metadata;
        await handler.ChallengeAsync(null);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Null(context.Response.ContentType);
        Assert.Equal(0, context.Response.Body.Length);
    }
}
