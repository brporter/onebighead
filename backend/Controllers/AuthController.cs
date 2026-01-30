using backend.Authentication;
using backend.Data;
using backend.DTOs;
using backend.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace backend.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IOidcTokenValidator _tokenValidator;
    private readonly ITokenService _tokenService;
    private readonly IUserRepository _userRepository;
    private readonly ITenantRepository _tenantRepository;
    private readonly IOAuthService _oauthService;
    private readonly AuthenticationSettings _settings;
    private readonly ILogger<AuthController> _logger;

    private const string OAuthStateCookieName = "oauth_state";

    public AuthController(
        IOidcTokenValidator tokenValidator,
        ITokenService tokenService,
        IUserRepository userRepository,
        ITenantRepository tenantRepository,
        IOAuthService oauthService,
        IOptions<AuthenticationSettings> settings,
        ILogger<AuthController> logger)
    {
        _tokenValidator = tokenValidator;
        _tokenService = tokenService;
        _userRepository = userRepository;
        _tenantRepository = tenantRepository;
        _oauthService = oauthService;
        _settings = settings.Value;
        _logger = logger;
    }

    /// <summary>
    /// Initiates the OAuth login flow by redirecting to the identity provider
    /// </summary>
    [HttpGet("login/{provider}")]
    public IActionResult Login(string provider, [FromQuery] string? returnUrl = null)
    {
        if (!Enum.TryParse<IdentityProvider>(provider, true, out var identityProvider))
        {
            return BadRequest(new { error = "Invalid identity provider" });
        }

        try
        {
            // Generate and store state for CSRF protection
            var state = _oauthService.GenerateSecureState();
            
            // Store state in an HTTP-only cookie for validation on callback
            Response.Cookies.Append(OAuthStateCookieName, state, new CookieOptions
            {
                HttpOnly = true,
                Secure = _settings.Cookie.Secure,
                SameSite = SameSiteMode.Lax, // Lax is required for OAuth redirects
                MaxAge = TimeSpan.FromMinutes(10),
                Path = "/"
            });

            // Store return URL in state cookie if provided
            if (!string.IsNullOrEmpty(returnUrl))
            {
                Response.Cookies.Append("oauth_return_url", returnUrl, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = _settings.Cookie.Secure,
                    SameSite = SameSiteMode.Lax,
                    MaxAge = TimeSpan.FromMinutes(10),
                    Path = "/"
                });
            }

            var authUrl = _oauthService.GenerateAuthorizationUrl(identityProvider, state);
            return Redirect(authUrl);
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning("Login attempt for disabled provider: {Provider}", provider);
            return Redirect($"{_settings.OAuth.PostLoginErrorUrl}?error={Uri.EscapeDataString(ex.Message)}");
        }
    }

    /// <summary>
    /// Handles the OAuth callback from identity providers (GET for Google/Microsoft)
    /// </summary>
    [HttpGet("callback/{provider}")]
    public async Task<IActionResult> CallbackGet(
        string provider,
        [FromQuery] string? code = null,
        [FromQuery] string? state = null,
        [FromQuery] string? error = null,
        [FromQuery] string? error_description = null)
    {
        return await HandleOAuthCallback(provider, code, state, error, error_description);
    }

    /// <summary>
    /// Handles the OAuth callback from identity providers (POST for Apple)
    /// </summary>
    [HttpPost("callback/{provider}")]
    public async Task<IActionResult> CallbackPost(
        string provider,
        [FromForm] string? code = null,
        [FromForm] string? state = null,
        [FromForm] string? error = null,
        [FromForm] string? error_description = null)
    {
        return await HandleOAuthCallback(provider, code, state, error, error_description);
    }

    private async Task<IActionResult> HandleOAuthCallback(
        string provider,
        string? code,
        string? state,
        string? error,
        string? errorDescription)
    {
        // Check for errors from the provider
        if (!string.IsNullOrEmpty(error))
        {
            _logger.LogWarning("OAuth error from {Provider}: {Error} - {Description}", 
                provider, error, errorDescription);
            return RedirectToError($"Authentication failed: {errorDescription ?? error}");
        }

        if (!Enum.TryParse<IdentityProvider>(provider, true, out var identityProvider))
        {
            return RedirectToError("Invalid identity provider");
        }

        // Validate state to prevent CSRF attacks
        var storedState = Request.Cookies[OAuthStateCookieName];
        if (!_oauthService.ValidateState(state ?? string.Empty, storedState ?? string.Empty))
        {
            _logger.LogWarning("OAuth state mismatch for {Provider}", provider);
            return RedirectToError("Invalid authentication state. Please try again.");
        }

        // Clear the state cookie
        Response.Cookies.Delete(OAuthStateCookieName);

        if (string.IsNullOrEmpty(code))
        {
            return RedirectToError("No authorization code received");
        }

        // Exchange code for tokens
        var tokenResponse = await _oauthService.ExchangeCodeForTokensAsync(code, identityProvider);
        if (!tokenResponse.Success || string.IsNullOrEmpty(tokenResponse.IdToken))
        {
            _logger.LogWarning("Token exchange failed for {Provider}: {Error}", provider, tokenResponse.Error);
            return RedirectToError(tokenResponse.Error ?? "Failed to authenticate");
        }

        // Validate the ID token using OIDC discovery
        var validationResult = await _tokenValidator.ValidateTokenAsync(tokenResponse.IdToken, identityProvider);
        if (!validationResult.IsValid)
        {
            _logger.LogWarning("Token validation failed for {Provider}: {Error}", provider, validationResult.Error);
            return RedirectToError(validationResult.Error ?? "Token validation failed");
        }

        // Look up or create user
        var user = await GetOrCreateUser(identityProvider, validationResult);
        if (user == null)
        {
            return RedirectToError("Failed to create user account");
        }

        // Generate app-specific JWT and set HTTP-only cookie
        var appToken = _tokenService.GenerateAppToken(user);
        SetAuthCookie(appToken);

        // Get return URL and redirect
        var returnUrl = Request.Cookies["oauth_return_url"] ?? _settings.OAuth.PostLoginRedirectUrl;
        Response.Cookies.Delete("oauth_return_url");

        _logger.LogInformation("User {Email} successfully authenticated via {Provider}", user.Email, provider);
        return Redirect(returnUrl);
    }

    private async Task<User?> GetOrCreateUser(IdentityProvider provider, OidcValidationResult validationResult)
    {
        var user = await _userRepository.GetByProviderIdAsync(provider, validationResult.Subject!);

        if (user is null)
        {
            // Check if user exists with same email but different provider
            user = await _userRepository.GetByEmailAsync(validationResult.Email!);

            if (user is null)
            {
                // Auto-provision new user with new tenant
                _logger.LogInformation("Auto-provisioning new user with email {Email}", validationResult.Email);
                user = await _userRepository.CreateWithNewTenantAsync(
                    validationResult.Email!,
                    provider,
                    validationResult.Subject!);
            }
            else
            {
                // User exists with same email but different provider
                _logger.LogInformation("User {Email} authenticated with different provider", validationResult.Email);
            }
        }

        return user;
    }

    private void SetAuthCookie(string token)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = _settings.Cookie.Secure,
            SameSite = Enum.Parse<SameSiteMode>(_settings.Cookie.SameSite, true),
            Expires = DateTimeOffset.UtcNow.AddDays(_settings.Jwt.AbsoluteExpirationDays),
            Path = "/"
        };

        Response.Cookies.Append(_settings.Cookie.Name, token, cookieOptions);
    }

    private IActionResult RedirectToError(string message)
    {
        return Redirect($"{_settings.OAuth.PostLoginErrorUrl}?error={Uri.EscapeDataString(message)}");
    }

    [HttpPost("callback")]
    public async Task<IActionResult> Callback([FromBody] AuthCallbackRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Token))
        {
            return BadRequest(new { error = "Token is required" });
        }

        if (!Enum.TryParse<IdentityProvider>(request.Provider, true, out var provider))
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
        var user = await GetOrCreateUser(provider, validationResult);
        if (user == null)
        {
            return StatusCode(500, new { error = "Failed to create user account" });
        }

        // Generate app-specific JWT and set cookie
        var appToken = _tokenService.GenerateAppToken(user);
        SetAuthCookie(appToken);

        return Ok(new AuthCallbackResponse
        {
            Success = true,
            Email = user.Email,
            TenantId = user.TenantId,
            TenantName = user.Tenant?.Name ?? string.Empty
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
        var tenantIdClaim = User.FindFirst("tenant_id")?.Value;
        var emailClaim = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;
        var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        var isAdmin = User.IsInRole("SystemAdministrator");

        if (string.IsNullOrEmpty(tenantIdClaim) || string.IsNullOrEmpty(userIdClaim))
        {
            return Unauthorized(new { error = "Not authenticated" });
        }

        var tenantId = int.Parse(tenantIdClaim);
        var tenant = await _tenantRepository.GetByIdAsync(tenantId);

        return Ok(new
        {
            userId = int.Parse(userIdClaim),
            email = emailClaim,
            tenantId = tenantId,
            tenantName = tenant?.Name ?? string.Empty,
            hasCompletedWelcome = tenant?.HasCompletedWelcome ?? false,
            isSystemAdministrator = isAdmin
        });
    }

    [HttpPost("complete-welcome")]
    public async Task<IActionResult> CompleteWelcome([FromBody] CompleteWelcomeRequest request)
    {
        var tenantIdClaim = User.FindFirst("tenant_id")?.Value;
        var emailClaim = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;

        if (string.IsNullOrEmpty(tenantIdClaim))
        {
            return Unauthorized(new { error = "Not authenticated" });
        }

        var tenantId = int.Parse(tenantIdClaim);
        var tenant = await _tenantRepository.GetByIdAsync(tenantId);

        if (tenant == null)
        {
            return NotFound(new { error = "Tenant not found" });
        }

        // Update tenant name if provided, otherwise use the user's email address
        if (!string.IsNullOrWhiteSpace(request.TenantName))
        {
            tenant.Name = request.TenantName.Trim();
        }
        else if (!string.IsNullOrEmpty(emailClaim))
        {
            tenant.Name = emailClaim;
        }

        tenant.HasCompletedWelcome = true;
        await _tenantRepository.UpdateAsync(tenant);

        _logger.LogInformation("Tenant {TenantId} completed welcome with name: {TenantName}", tenantId, tenant.Name);

        return Ok(new
        {
            tenantId = tenant.Id,
            tenantName = tenant.Name,
            hasCompletedWelcome = tenant.HasCompletedWelcome
        });
    }
}

public class AuthCallbackRequest
{
    public string Token { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty;
}

public class AuthCallbackResponse
{
    public bool Success { get; set; }
    public string Email { get; set; } = string.Empty;
    public int TenantId { get; set; }
    public string TenantName { get; set; } = string.Empty;
}

