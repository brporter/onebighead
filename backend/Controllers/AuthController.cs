using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IOidcTokenValidator _tokenValidator;
    private readonly ITokenService _tokenService;
    private readonly IUserRepository _userRepository;
    private readonly IWorkspaceRepository _workspaceRepository;
    private readonly IWorkspaceUserRepository _workspaceUserRepository;
    private readonly IOAuthService _oauthService;
    private readonly AuthenticationSettings _settings;
    private readonly ILogger<AuthController> _logger;

    private const string OAuthStateCookieName = "oauth_state";

    public AuthController(
        IOidcTokenValidator tokenValidator,
        ITokenService tokenService,
        IUserRepository userRepository,
        IWorkspaceRepository workspaceRepository,
        IWorkspaceUserRepository workspaceUserRepository,
        IOAuthService oauthService,
        IOptions<AuthenticationSettings> settings,
        ILogger<AuthController> logger)
    {
        _tokenValidator = tokenValidator;
        _tokenService = tokenService;
        _userRepository = userRepository;
        _workspaceRepository = workspaceRepository;
        _workspaceUserRepository = workspaceUserRepository;
        _oauthService = oauthService;
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
    [EnableRateLimiting("auth-callback")]
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
    [EnableRateLimiting("auth-callback")]
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
        var (user, workspaceRole) = await GetOrCreateUser(identityProvider, validationResult);
        if (user == null)
        {
            return RedirectToError("Failed to create user account");
        }

        // Generate app-specific JWT and set HTTP-only cookie
        var appToken = _tokenService.GenerateAppToken(user, workspaceRole);
        SetAuthCookie(appToken);

        // Get return URL and redirect
        var returnUrl = Request.Cookies["oauth_return_url"] ?? _settings.OAuth.PostLoginRedirectUrl;
        Response.Cookies.Delete("oauth_return_url");

        _logger.LogInformation("User {Email} successfully authenticated via {Provider}", user.Email, provider);
        return Redirect(returnUrl);
    }

    private async Task<(User? user, WorkspaceRole workspaceRole)> GetOrCreateUser(IdentityProvider provider, OidcValidationResult validationResult)
    {
        // 1. Check for existing linked user by provider ID
        var user = await _userRepository.GetByProviderIdAsync(provider, validationResult.Subject!);
        if (user != null)
        {
            // Restore soft-deleted user
            if (user.IsDeleted)
            {
                user.IsDeleted = false;
                user.DeletedAt = null;
                await _userRepository.UpdateAsync(user);
                _logger.LogInformation("Restored soft-deleted user {UserId} ({Email}) on sign-in",
                    user.Id, user.Email);
            }

            var membership = await _workspaceUserRepository.GetMembershipAsync(user.Id, user.ActiveWorkspaceId);
            return (user, membership?.WorkspaceRole ?? WorkspaceRole.Normal);
        }

        // 2. Check for pending user by email (email linking)
        var pendingUser = await _userRepository.GetByEmailAsync(validationResult.Email!);
        if (pendingUser != null && !pendingUser.IsLinked)
        {
            // Restore if soft-deleted
            if (pendingUser.IsDeleted)
            {
                pendingUser.IsDeleted = false;
                pendingUser.DeletedAt = null;
                await _userRepository.UpdateAsync(pendingUser);
                _logger.LogInformation("Restored soft-deleted pending user {UserId} on link", pendingUser.Id);
            }

            // Link pending user to this OAuth identity
            _logger.LogInformation("Linking pending user {Email} to {Provider}", validationResult.Email, provider);
            var linkedUser = await _userRepository.LinkUserAsync(
                pendingUser.Id, provider, validationResult.Subject!);
            if (linkedUser != null)
            {
                var membership = await _workspaceUserRepository.GetMembershipAsync(linkedUser.Id, linkedUser.ActiveWorkspaceId);
                return (linkedUser, membership?.WorkspaceRole ?? WorkspaceRole.Normal);
            }
            return (null, WorkspaceRole.Normal);
        }

        if (pendingUser != null)
        {
            // User exists with same email but different provider (already linked)
            // Restore if soft-deleted
            if (pendingUser.IsDeleted)
            {
                pendingUser.IsDeleted = false;
                pendingUser.DeletedAt = null;
                await _userRepository.UpdateAsync(pendingUser);
                _logger.LogInformation("Restored soft-deleted user {UserId} ({Email}) on sign-in with different provider",
                    pendingUser.Id, pendingUser.Email);
            }
            _logger.LogInformation("User {Email} authenticated with different provider", validationResult.Email);
            var membership = await _workspaceUserRepository.GetMembershipAsync(pendingUser.Id, pendingUser.ActiveWorkspaceId);
            return (pendingUser, membership?.WorkspaceRole ?? WorkspaceRole.Normal);
        }

        // 3. Auto-provision new user with new workspace (first-time signup)
        _logger.LogInformation("Auto-provisioning new user with email {Email}", validationResult.Email);
        var newUser = await _userRepository.CreateWithNewWorkspaceAsync(
            validationResult.Email!,
            provider,
            validationResult.Subject!);
        // New users are WorkspaceAdmin of their own workspace
        return (newUser, WorkspaceRole.WorkspaceAdmin);
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
    [EnableRateLimiting("auth-callback")]
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
        var (user, workspaceRole) = await GetOrCreateUser(provider, validationResult);
        if (user == null)
        {
            return StatusCode(500, new { error = "Failed to create user account" });
        }

        // Generate app-specific JWT and set cookie
        var appToken = _tokenService.GenerateAppToken(user, workspaceRole);
        SetAuthCookie(appToken);

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
        var workspaceIdClaim = User.FindFirst("workspace_id")?.Value;
        var emailClaim = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;
        var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        var workspaceRoleClaim = User.FindFirst("workspace_role")?.Value;
        var isAdmin = User.IsInRole("SystemAdministrator");

        if (string.IsNullOrEmpty(workspaceIdClaim) || string.IsNullOrEmpty(userIdClaim) ||
            !int.TryParse(workspaceIdClaim, out var workspaceId) || !int.TryParse(userIdClaim, out var userId))
        {
            return Unauthorized(new { error = "Not authenticated" });
        }
        var workspace = await _workspaceRepository.GetByIdAsync(workspaceId);
        var user = await _userRepository.GetByIdAsync(userId);

        // Get all workspace memberships for this user (excluding deleted workspaces)
        var memberships = await _workspaceUserRepository.GetByUserIdAsync(userId);
        var workspaceMemberships = memberships
            .Where(m => m.Workspace != null && !m.Workspace.IsDeleted)
            .Select(m => new WorkspaceMembershipResponse
            {
                WorkspaceId = m.WorkspaceId,
                WorkspaceName = m.Workspace!.Name,
                WorkspaceRole = m.WorkspaceRole,
                HasCompletedWelcome = m.Workspace.HasCompletedWelcome
            }).ToList();

        var activeWorkspaceRole = workspaceRoleClaim ?? "Normal";

        return Ok(new
        {
            userId = userId,
            email = emailClaim,
            // Active workspace info
            activeWorkspace = new WorkspaceMembershipResponse
            {
                WorkspaceId = workspaceId,
                WorkspaceName = workspace?.Name ?? string.Empty,
                WorkspaceRole = Enum.Parse<WorkspaceRole>(activeWorkspaceRole),
                HasCompletedWelcome = workspace?.HasCompletedWelcome ?? false
            },
            // All workspace memberships
            workspaces = workspaceMemberships,
            // Legacy fields for backwards compatibility
            workspaceId = workspaceId,
            workspaceName = workspace?.Name ?? string.Empty,
            hasCompletedWelcome = workspace?.HasCompletedWelcome ?? false,
            hasAcceptedTerms = user?.HasAcceptedTerms ?? false,
            isSystemAdministrator = isAdmin,
            workspaceRole = activeWorkspaceRole,
            isWorkspaceAdmin = activeWorkspaceRole == "WorkspaceAdmin"
        });
    }

    [HttpPost("accept-terms")]
    public async Task<IActionResult> AcceptTerms()
    {
        var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

        if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out var userId))
        {
            return Unauthorized(new { error = "Not authenticated" });
        }

        var user = await _userRepository.GetByIdAsync(userId);

        if (user == null)
        {
            return NotFound(new { error = "User not found" });
        }

        user.AcceptedTermsAt = DateTime.UtcNow;
        await _userRepository.UpdateAsync(user);

        _logger.LogInformation("User {UserId} ({Email}) accepted Terms of Service and Privacy Policy", userId, user.Email);

        return Ok(new
        {
            hasAcceptedTerms = true,
            acceptedTermsAt = user.AcceptedTermsAt
        });
    }

    [HttpPost("complete-welcome")]
    public async Task<IActionResult> CompleteWelcome([FromBody] CompleteWelcomeRequest request)
    {
        var workspaceIdClaim = User.FindFirst("workspace_id")?.Value;
        var emailClaim = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;

        if (string.IsNullOrEmpty(workspaceIdClaim) || !int.TryParse(workspaceIdClaim, out var workspaceId))
        {
            return Unauthorized(new { error = "Not authenticated" });
        }

        var workspace = await _workspaceRepository.GetByIdAsync(workspaceId);

        if (workspace == null)
        {
            return NotFound(new { error = "Workspace not found" });
        }

        // Update workspace name if provided, otherwise use the user's email address
        if (!string.IsNullOrWhiteSpace(request.WorkspaceName))
        {
            workspace.Name = request.WorkspaceName.Trim();
        }
        else if (!string.IsNullOrEmpty(emailClaim))
        {
            workspace.Name = emailClaim;
        }

        workspace.HasCompletedWelcome = true;
        await _workspaceRepository.UpdateAsync(workspace);

        _logger.LogInformation("Workspace {WorkspaceId} completed welcome with name: {WorkspaceName}", workspaceId, workspace.Name);

        return Ok(new
        {
            workspaceId = workspace.Id,
            workspaceName = workspace.Name,
            hasCompletedWelcome = workspace.HasCompletedWelcome
        });
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

            var membership = await _workspaceUserRepository.GetMembershipAsync(user.Id, user.ActiveWorkspaceId);
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
        SetAuthCookie(appToken);

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

