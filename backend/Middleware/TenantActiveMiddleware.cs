using System.Security.Claims;
using System.Text.Json;
using OneBigHead.Server.Services;

namespace OneBigHead.Server.Middleware;

/// <summary>
/// Middleware that checks if the user's current tenant has been soft-deleted.
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

        // Skip excluded paths (auth endpoints, deletion info, health check)
        if (ExcludedPrefixes.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
        {
            await _next(context);
            return;
        }

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
