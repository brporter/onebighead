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

namespace OneBigHead.Server.Controllers;

[AllowInactiveWorkspace]
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IOidcTokenValidator _tokenValidator;
    private readonly ITokenService _tokenService;
    private readonly IUserRepository _userRepository;
    private readonly IWorkspaceRepository _workspaceRepository;
    private readonly IWorkspaceUserRepository _workspaceUserRepository;
    private readonly IExternalUserService _externalUsers;
    private readonly AuthenticationSettings _settings;
    private readonly ILogger<AuthController> _logger;


    public AuthController(
        IOidcTokenValidator tokenValidator,
        ITokenService tokenService,
        IUserRepository userRepository,
        IWorkspaceRepository workspaceRepository,
        IWorkspaceUserRepository workspaceUserRepository,
        IExternalUserService externalUsers,
        IOptions<AuthenticationSettings> settings,
        ILogger<AuthController> logger)
    {
        _tokenValidator = tokenValidator;
        _tokenService = tokenService;
        _userRepository = userRepository;
        _workspaceRepository = workspaceRepository;
        _workspaceUserRepository = workspaceUserRepository;
        _externalUsers = externalUsers;
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
        var (user, workspaceRole) = await _externalUsers.GetOrCreateAsync(provider, validationResult);
        if (user == null)
        {
            return StatusCode(500, new { error = "Failed to create user account" });
        }

        // Generate app-specific JWT and set cookie
        var appToken = _tokenService.GenerateAppToken(user, workspaceRole);
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
        var workspaceIdClaim = User.FindFirst(ClaimNames.WorkspaceId)?.Value;
        var emailClaim = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;
        var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        var workspaceRoleClaim = User.FindFirst(ClaimNames.WorkspaceRole)?.Value;
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
                HasCompletedWelcome = m.Workspace.HasCompletedWelcome,
                Slug = m.Workspace.Slug
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
                HasCompletedWelcome = workspace?.HasCompletedWelcome ?? false,
                Slug = workspace?.Slug
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
        var workspaceIdClaim = User.FindFirst(ClaimNames.WorkspaceId)?.Value;
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

