using Microsoft.AspNetCore.Authentication;
using OneBigHead.Server.Middleware;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Extensions;
using OneBigHead.Server.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using OneBigHead.Server.Services.Accounts;

namespace OneBigHead.Server.Controllers;

[AllowInactiveWorkspace]
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IOidcTokenValidator _tokenValidator;
    private readonly ITokenService _tokenService;
    private readonly IUserRepository _userRepository;
    private readonly IWorkspaceUserRepository _workspaceUserRepository;
    private readonly IExternalUserService _externalUsers;
    private readonly ICurrentUserSessionReader _sessions;
    private readonly IAccountTerms _accountTerms;
    private readonly AuthenticationSettings _settings;
    private readonly ILogger<AuthController> _logger;


    public AuthController(
        IOidcTokenValidator tokenValidator,
        ITokenService tokenService,
        IUserRepository userRepository,
        IWorkspaceUserRepository workspaceUserRepository,
        IExternalUserService externalUsers,
        ICurrentUserSessionReader sessions,
        IAccountTerms accountTerms,
        IOptions<AuthenticationSettings> settings,
        ILogger<AuthController> logger)
    {
        _tokenValidator = tokenValidator;
        _tokenService = tokenService;
        _userRepository = userRepository;
        _workspaceUserRepository = workspaceUserRepository;
        _externalUsers = externalUsers;
        _sessions = sessions;
        _accountTerms = accountTerms;
        _settings = settings.Value;
        _logger = logger;
    }

    /// <summary>
    /// Initiates the OAuth login flow by redirecting to the identity provider
    /// </summary>
    [HttpGet("login/{provider}")]
    [EnableRateLimiting("auth-login")]
    public IActionResult Login(string provider, [FromQuery] string? returnUrl = null)
    {
        if (!Enum.TryParse<IdentityProvider>(provider, true, out var identityProvider) ||
            !Enum.IsDefined(identityProvider) || identityProvider == IdentityProvider.None)
            return BadRequest(new { error = "Invalid identity provider" });

        if (!_settings.Providers.Get(identityProvider).IsConfigured)
            return RedirectToError($"Provider {identityProvider} is not enabled");

        // AuthenticationProperties are protected by the OIDC handler along with correlation and nonce.
        return Challenge(new AuthenticationProperties
        {
            RedirectUri = Url.IsLocalUrl(returnUrl) ? returnUrl : _settings.OAuth.PostLoginRedirectUrl
        }, identityProvider.ToString());
    }

    // Enabled providers are handled by the OIDC middleware before this action.
    // Keeping an endpoint supplies routing metadata for the callback rate limiter.
    [AcceptVerbs("GET", "POST")]
    [Route("callback/{provider}")]
    [EnableRateLimiting("auth-callback")]
    public IActionResult UnavailableCallback() => RedirectToError("Invalid or disabled identity provider");

    private IActionResult RedirectToError(string message)
    {
        return Redirect($"{_settings.OAuth.PostLoginErrorUrl}?error={Uri.EscapeDataString(message)}");
    }

    [HttpPost("callback")]
    [EnableRateLimiting("auth-callback")]
    public async Task<IActionResult> Callback([FromBody] AuthCallbackRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Token))
        {
            return BadRequest(new { error = "Token is required" });
        }

        if (!Enum.TryParse<IdentityProvider>(request.Provider, true, out var provider) ||
            !Enum.IsDefined(provider) || provider == IdentityProvider.None)
        {
            return BadRequest(new { error = "Invalid identity provider" });
        }

        // Validate the federated token using OIDC discovery
        var validationResult = await _tokenValidator.ValidateTokenAsync(request.Token, provider);

        if (!validationResult.IsValid)
        {
            _logger.LogWarning("Token validation failed: {Error}", validationResult.Error);
            return Unauthorized(new { error = validationResult.Error });
        }

        // Look up or create user
        var signIn = await _externalUsers.GetOrCreateAsync(provider, validationResult, HttpContext.RequestAborted);
        var user = signIn.User;
        if (user == null)
        {
            return Unauthorized(new { error = signIn.Error ?? ExternalSignInResult.DefaultError });
        }

        // Generate app-specific JWT and set cookie
        var appToken = _tokenService.GenerateAppToken(user, signIn.WorkspaceRole);
        Response.SetAuthCookie(appToken, _settings);

        return Ok(new AuthCallbackResponse
        {
            Success = true,
            Email = user.Email,
            WorkspaceId = user.ActiveWorkspaceId,
            WorkspaceName = user.ActiveWorkspace?.Name ?? string.Empty
        });
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        Response.Cookies.Delete(_settings.Cookie.Name, new CookieOptions
        {
            HttpOnly = true,
            Secure = _settings.Cookie.Secure,
            SameSite = Enum.Parse<SameSiteMode>(_settings.Cookie.SameSite, true),
            Path = "/"
        });

        return Ok(new { success = true });
    }

    [HttpGet("me")]
    public async Task<IActionResult> GetCurrentUser()
    {
        if (User.Identity?.IsAuthenticated != true ||
            !int.TryParse(User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value, out var userId))
            return Unauthorized(new { error = "Not authenticated" });

        var session = await _sessions.ReadAsync(userId);
        if (session is null) return Unauthorized(new { error = "Not authenticated" });
        Response.Headers.CacheControl = "no-store";
        Response.SetAuthCookie(_tokenService.GenerateAppToken(session.User, session.Response.WorkspaceRole), _settings);
        return Ok(session.Response);
    }

    [HttpPost("accept-terms")]
    public async Task<IActionResult> AcceptTerms()
    {
        var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

        if (!int.TryParse(userIdClaim, out var userId) || userId <= 0)
        {
            return Unauthorized(new { error = "Not authenticated" });
        }

        var acceptedAt = await _accountTerms.AcceptAsync(userId, HttpContext.RequestAborted);

        if (acceptedAt is null)
        {
            return NotFound(new { error = "User not found" });
        }

        _logger.LogInformation("User {UserId} accepted Terms of Service and Privacy Policy", userId);
        return Ok(new AcceptTermsResponse(true, acceptedAt.Value));
    }

#if DEBUG
    /// <summary>
    /// Development-only endpoint for test authentication.
    /// Logs in as the specified email address, creating the user if needed.
    /// </summary>
    [HttpPost("dev-login")]
    public async Task<IActionResult> DevLogin([FromBody] DevLoginRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Email))
        {
            return BadRequest(new { error = "Email is required" });
        }

        var email = request.Email.Trim().ToLowerInvariant();
        _logger.LogWarning("DEV LOGIN: Authenticating as {Email} - THIS SHOULD NEVER APPEAR IN PRODUCTION", email);

        // Look up existing user by email
        var user = await _userRepository.GetByEmailAsync(email);
        WorkspaceRole workspaceRole;

        if (user != null)
        {
            // Restore if soft-deleted
            if (user.IsDeleted)
            {
                user.IsDeleted = false;
                user.DeletedAt = null;
                await _userRepository.UpdateAsync(user);
                _logger.LogInformation("DEV LOGIN: Restored soft-deleted user {UserId}", user.Id);
            }

            var membership = user.ActiveWorkspaceId is int workspaceId
                ? await _workspaceUserRepository.GetMembershipAsync(user.Id, workspaceId)
                : null;
            workspaceRole = membership?.WorkspaceRole ?? WorkspaceRole.Normal;
        }
        else
        {
            // Create new user with new workspace
            user = await _userRepository.CreateWithNewWorkspaceAsync(
                email,
                IdentityProvider.Microsoft, // Use Microsoft as placeholder provider
                $"dev-{Guid.NewGuid()}"); // Fake provider subject ID
            workspaceRole = WorkspaceRole.WorkspaceAdmin;
            _logger.LogInformation("DEV LOGIN: Created new user {UserId} with workspace {WorkspaceId}", user.Id, user.ActiveWorkspaceId);
        }

        // Generate JWT and set cookie
        var appToken = _tokenService.GenerateAppToken(user, workspaceRole);
        Response.SetAuthCookie(appToken, _settings);

        return Ok(new
        {
            success = true,
            userId = user.Id,
            email = user.Email,
            workspaceId = user.ActiveWorkspaceId,
            workspaceRole = workspaceRole.ToString(),
            isNewUser = user.CreatedAt > DateTime.UtcNow.AddSeconds(-5)
        });
    }
#endif
}

