using System.Security.Claims;
using System.Text.Json;
using OneBigHead.Server.Services;

namespace OneBigHead.Server.Middleware;

/// <summary>
/// Middleware that checks if the user and their current tenant are active.
/// Returns 401 Unauthorized with USER_DELETED code if user is soft-deleted or has no active tenants.
/// Returns 410 Gone if the tenant is deleted, allowing the client to handle the situation.
/// </summary>
public class TenantActiveMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<TenantActiveMiddleware> _logger;

    // Paths that should be accessible even when tenant is deleted
    private static readonly string[] ExcludedPrefixes =
    {
        "/api/auth",
        "/api/users/me/deletion-info",
        "/api/users/me/restorable-tenants",
        "/api/themes",
        "/health"
    };

    // Paths that need tenant context but should be accessible (for tenant switching)
    private static readonly string[] TenantManagementPaths =
    {
        "/api/tenants"
    };

    public TenantActiveMiddleware(RequestDelegate next, ILogger<TenantActiveMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, ITenantDeletionService tenantDeletionService)
    {
        var path = context.Request.Path.Value ?? "";

        // Skip excluded paths (auth endpoints, deletion info, health check, themes)
        if (ExcludedPrefixes.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
        {
            _logger.LogDebug("Path {Path} matched excluded prefix, skipping tenant check", path);
            await _next(context);
            return;
        }

        _logger.LogDebug("Path {Path} did not match any excluded prefix", path);

        // Allow tenant listing and switching (GET /api/tenants, POST /api/tenants/{id}/switch)
        if (path.StartsWith("/api/tenants", StringComparison.OrdinalIgnoreCase))
        {
            // Allow GET /api/tenants (list tenants)
            if (path.Equals("/api/tenants", StringComparison.OrdinalIgnoreCase) &&
                context.Request.Method == "GET")
            {
                await _next(context);
                return;
            }

            // Allow POST /api/tenants/{id}/switch (switch tenant)
            if (path.EndsWith("/switch", StringComparison.OrdinalIgnoreCase) &&
                context.Request.Method == "POST")
            {
                await _next(context);
                return;
            }

            // Allow POST /api/tenants (create new tenant)
            if (path.Equals("/api/tenants", StringComparison.OrdinalIgnoreCase) &&
                context.Request.Method == "POST")
            {
                await _next(context);
                return;
            }

            // Allow POST /api/tenants/setup (setup new tenant)
            if (path.Equals("/api/tenants/setup", StringComparison.OrdinalIgnoreCase) &&
                context.Request.Method == "POST")
            {
                await _next(context);
                return;
            }

            // Allow POST /api/tenants/restore (restore multiple tenants)
            if (path.Equals("/api/tenants/restore", StringComparison.OrdinalIgnoreCase) &&
                context.Request.Method == "POST")
            {
                await _next(context);
                return;
            }

            // Allow POST /api/tenants/{id}/restore (restore single tenant)
            if (path.EndsWith("/restore", StringComparison.OrdinalIgnoreCase) &&
                context.Request.Method == "POST")
            {
                await _next(context);
                return;
            }
        }

        // Get user ID from claims
        var userIdClaim = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!string.IsNullOrEmpty(userIdClaim) && int.TryParse(userIdClaim, out var userId))
        {
            // Check if user is soft-deleted
            var isUserDeleted = await tenantDeletionService.IsUserDeletedAsync(userId);
            if (isUserDeleted)
            {
                _logger.LogWarning("Request blocked for deleted user {UserId} at path {Path}",
                    userId, path);

                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";
                context.Response.Headers.CacheControl = "no-store";

                var response = new
                {
                    error = "Your account has been deleted. Please sign in again to restore your account.",
                    code = "USER_DELETED"
                };

                await context.Response.WriteAsync(JsonSerializer.Serialize(response));
                return;
            }

            // Check if user has any active tenants
            var hasActiveTenant = await tenantDeletionService.HasUserAnyActiveTenantAsync(userId);
            if (!hasActiveTenant)
            {
                _logger.LogWarning("Request blocked for user {UserId} with no active tenants at path {Path}",
                    userId, path);

                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";
                context.Response.Headers.CacheControl = "no-store";

                var response = new
                {
                    error = "You have no active workspaces. Please create or restore a workspace.",
                    code = "NO_ACTIVE_TENANTS"
                };

                await context.Response.WriteAsync(JsonSerializer.Serialize(response));
                return;
            }
        }

        // Get tenant ID from claims
        var tenantIdClaim = context.User.FindFirst("tenant_id")?.Value;
        if (string.IsNullOrEmpty(tenantIdClaim) || !int.TryParse(tenantIdClaim, out var tenantId))
        {
            // No tenant in token, let the request proceed (will likely fail auth)
            await _next(context);
            return;
        }

        // Check if tenant is deleted
        var isDeleted = await tenantDeletionService.IsTenantDeletedAsync(tenantId);
        if (isDeleted)
        {
            _logger.LogWarning("Request blocked for deleted tenant {TenantId} at path {Path}",
                tenantId, path);

            context.Response.StatusCode = StatusCodes.Status410Gone;
            context.Response.ContentType = "application/json";
            // Prevent browsers from caching 410 responses - user may create/restore a tenant
            context.Response.Headers.CacheControl = "no-store";

            var response = new
            {
                error = "This organization has been deleted. Please switch to another organization or create a new one.",
                code = "TENANT_DELETED"
            };

            await context.Response.WriteAsync(JsonSerializer.Serialize(response));
            return;
        }

        await _next(context);
    }
}

/// <summary>
/// Extension methods for registering tenant active middleware.
/// </summary>
public static class TenantActiveMiddlewareExtensions
{
    public static IApplicationBuilder UseTenantActiveCheck(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<TenantActiveMiddleware>();
    }
}
