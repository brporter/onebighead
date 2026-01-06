using backend.Authentication;
using backend.Data;
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
    private readonly AuthenticationSettings _settings;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        IOidcTokenValidator tokenValidator,
        ITokenService tokenService,
        IUserRepository userRepository,
        IOptions<AuthenticationSettings> settings,
        ILogger<AuthController> logger)
    {
        _tokenValidator = tokenValidator;
        _tokenService = tokenService;
        _userRepository = userRepository;
        _settings = settings.Value;
        _logger = logger;
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
                // User exists with same email but different provider - could update provider or reject
                // For now, we'll use the existing user's tenant
                _logger.LogInformation("User {Email} authenticated with different provider", validationResult.Email);
            }
        }

        // Generate app-specific JWT
        var appToken = _tokenService.GenerateAppToken(user);

        // Set HTTP-only cookie
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = _settings.Cookie.Secure,
            SameSite = Enum.Parse<SameSiteMode>(_settings.Cookie.SameSite, true),
            Expires = DateTimeOffset.UtcNow.AddDays(_settings.Jwt.AbsoluteExpirationDays),
            Path = "/"
        };

        Response.Cookies.Append(_settings.Cookie.Name, appToken, cookieOptions);

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
    public IActionResult GetCurrentUser()
    {
        var tenantIdClaim = User.FindFirst("tenant_id")?.Value;
        var emailClaim = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;
        var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

        if (string.IsNullOrEmpty(tenantIdClaim) || string.IsNullOrEmpty(userIdClaim))
        {
            return Unauthorized(new { error = "Not authenticated" });
        }

        return Ok(new
        {
            userId = int.Parse(userIdClaim),
            email = emailClaim,
            tenantId = int.Parse(tenantIdClaim)
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

