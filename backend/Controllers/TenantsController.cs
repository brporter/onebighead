using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace OneBigHead.Server.Controllers;

[Route("api/[controller]")]
[Authorize]
public class TenantsController : ApiControllerBase
{
    private readonly ITenantRepository _tenantRepository;
    private readonly ITenantUserRepository _tenantUserRepository;
    private readonly IUserRepository _userRepository;
    private readonly ITokenService _tokenService;
    private readonly AuthenticationSettings _settings;
    private readonly ILogger<TenantsController> _logger;

    public TenantsController(
        ITenantRepository tenantRepository,
        ITenantUserRepository tenantUserRepository,
        IUserRepository userRepository,
        ITokenService tokenService,
        IOptions<AuthenticationSettings> settings,
        ILogger<TenantsController> logger)
    {
        _tenantRepository = tenantRepository;
        _tenantUserRepository = tenantUserRepository;
        _userRepository = userRepository;
        _tokenService = tokenService;
        _settings = settings.Value;
        _logger = logger;
    }

    /// <summary>
    /// List all tenant memberships for the current user
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetTenants()
    {
        var userId = GetUserId();
        var memberships = await _tenantUserRepository.GetByUserIdAsync(userId);

        var response = memberships.Select(m => new TenantMembershipResponse
        {
            TenantId = m.TenantId,
            TenantName = m.Tenant.Name,
            TenantRole = m.TenantRole,
            HasCompletedWelcome = m.Tenant.HasCompletedWelcome
        }).ToList();

        return Ok(response);
    }

    /// <summary>
    /// Create a new tenant and add the current user as TenantAdmin
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> CreateTenant([FromBody] CreateTenantRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest(new { error = "Tenant name is required" });
        }

        var userId = GetUserId();

        // Check if user has exactly 1 tenant (business rule)
        var membershipCount = await _tenantUserRepository.CountUserMembershipsAsync(userId);
        if (membershipCount != 1)
        {
            return BadRequest(new { error = "You can only create a new tenant if you have exactly one existing membership" });
        }

        // Create the new tenant
        var tenant = new Tenant
        {
            Name = request.Name.Trim(),
            HasCompletedWelcome = false,
            CreatedAt = DateTime.UtcNow
        };

        await _tenantRepository.CreateAsync(tenant);

        // Add user as TenantAdmin of the new tenant
        await _tenantUserRepository.CreateAsync(userId, tenant.Id, TenantRole.TenantAdmin);

        _logger.LogInformation("User {UserId} created new tenant {TenantId} ({TenantName})", userId, tenant.Id, tenant.Name);

        return Ok(new CreateTenantResponse
        {
            TenantId = tenant.Id,
            TenantName = tenant.Name,
            TenantRole = TenantRole.TenantAdmin,
            HasCompletedWelcome = false
        });
    }

    /// <summary>
    /// Switch the current user's active tenant
    /// </summary>
    [HttpPost("{tenantId}/switch")]
    public async Task<IActionResult> SwitchTenant(int tenantId)
    {
        var userId = GetUserId();

        // Verify user is a member of the target tenant
        var membership = await _tenantUserRepository.GetMembershipAsync(userId, tenantId);
        if (membership == null)
        {
            return Forbid();
        }

        // Update user's active tenant
        await _userRepository.UpdateActiveTenantAsync(userId, tenantId);

        // Get updated user and generate new token
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            return NotFound(new { error = "User not found" });
        }

        // Generate new JWT with updated tenant
        var appToken = _tokenService.GenerateAppToken(user, membership.TenantRole);
        SetAuthCookie(appToken);

        _logger.LogInformation("User {UserId} switched to tenant {TenantId}", userId, tenantId);

        return Ok(new SwitchTenantResponse
        {
            Success = true,
            TenantId = tenantId,
            TenantName = membership.Tenant.Name
        });
    }

    /// <summary>
    /// Leave a tenant (remove membership)
    /// </summary>
    [HttpDelete("{tenantId}/membership")]
    public async Task<IActionResult> LeaveTenant(int tenantId)
    {
        var userId = GetUserId();

        // Verify user is a member of this tenant
        var membership = await _tenantUserRepository.GetMembershipAsync(userId, tenantId);
        if (membership == null)
        {
            return NotFound(new { error = "You are not a member of this tenant" });
        }

        // Check if this is the user's only tenant
        var membershipCount = await _tenantUserRepository.CountUserMembershipsAsync(userId);
        if (membershipCount <= 1)
        {
            return BadRequest(new { error = "Cannot leave your only tenant" });
        }

        // If user is TenantAdmin, check if there are other admins
        if (membership.TenantRole == TenantRole.TenantAdmin)
        {
            var adminCount = await _tenantUserRepository.CountAdminsInTenantAsync(tenantId);
            if (adminCount <= 1)
            {
                return BadRequest(new { error = "Cannot leave: you are the only admin in this tenant. Promote another user to admin first." });
            }
        }

        // Get user's current active tenant
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            return NotFound(new { error = "User not found" });
        }

        var wasActiveTenant = user.ActiveTenantId == tenantId;

        // Remove membership
        await _tenantUserRepository.DeleteAsync(userId, tenantId);

        _logger.LogInformation("User {UserId} left tenant {TenantId}", userId, tenantId);

        // If this was their active tenant, we need to switch to another
        if (wasActiveTenant)
        {
            var remainingMemberships = await _tenantUserRepository.GetByUserIdAsync(userId);
            var nextTenant = remainingMemberships.FirstOrDefault();
            if (nextTenant != null)
            {
                await _userRepository.UpdateActiveTenantAsync(userId, nextTenant.TenantId);

                // Reload user and generate new token
                user = await _userRepository.GetByIdAsync(userId);
                if (user != null)
                {
                    var appToken = _tokenService.GenerateAppToken(user, nextTenant.TenantRole);
                    SetAuthCookie(appToken);
                }
            }
        }

        return Ok(new LeaveTenantResponse { Success = true });
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
}
