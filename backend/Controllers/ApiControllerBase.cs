using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace backend.Controllers;

/// <summary>
/// Base controller providing common functionality for API controllers.
/// </summary>
[ApiController]
public abstract class ApiControllerBase : ControllerBase
{
    /// <summary>
    /// Extracts and validates the tenant ID from the current user's claims.
    /// </summary>
    /// <returns>The tenant ID from the user's token.</returns>
    /// <exception cref="UnauthorizedAccessException">Thrown when tenant_id claim is missing or invalid.</exception>
    protected int GetTenantId()
    {
        var tenantIdClaim = User.FindFirst("tenant_id")?.Value;
        if (string.IsNullOrEmpty(tenantIdClaim) || !int.TryParse(tenantIdClaim, out var tenantId))
        {
            throw new UnauthorizedAccessException("Tenant ID not found in token");
        }
        return tenantId;
    }

    /// <summary>
    /// Attempts to extract the tenant ID from the current user's claims.
    /// </summary>
    /// <returns>The tenant ID if present and valid; otherwise, null.</returns>
    protected int? TryGetTenantId()
    {
        var tenantIdClaim = User.FindFirst("tenant_id")?.Value;
        if (string.IsNullOrEmpty(tenantIdClaim) || !int.TryParse(tenantIdClaim, out var tenantId))
        {
            return null;
        }
        return tenantId;
    }

    /// <summary>
    /// Extracts and validates the user ID from the current user's claims.
    /// </summary>
    /// <returns>The user ID from the user's token.</returns>
    /// <exception cref="UnauthorizedAccessException">Thrown when user ID claim is missing or invalid.</exception>
    protected int GetUserId()
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out var userId))
        {
            throw new UnauthorizedAccessException("User ID not found in token");
        }
        return userId;
    }
}
