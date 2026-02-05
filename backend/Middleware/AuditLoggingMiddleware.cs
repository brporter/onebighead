using System.Security.Claims;

namespace OneBigHead.Server.Middleware;

/// <summary>
/// Middleware for audit logging of sensitive operations.
/// Logs user ID, action, and target resource for state-changing requests.
/// </summary>
public class AuditLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<AuditLoggingMiddleware> _logger;

    // HTTP methods that modify state
    private static readonly HashSet<string> StateChangingMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        "POST", "PUT", "PATCH", "DELETE"
    };

    // Paths that require audit logging (case-insensitive prefix match)
    private static readonly string[] AuditedPaths =
    {
        "/api/users",
        "/api/workspaces",
        "/api/collections",
        "/api/categories",
        "/api/items",
        "/api/templates",
        "/api/admin",
        "/api/auth/accept-terms",
        "/api/auth/complete-welcome"
    };

    public AuditLoggingMiddleware(RequestDelegate next, ILogger<AuditLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Only log state-changing operations
        if (!StateChangingMethods.Contains(context.Request.Method))
        {
            await _next(context);
            return;
        }

        // Check if path should be audited
        var path = context.Request.Path.Value ?? "";
        var shouldAudit = AuditedPaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase));

        if (!shouldAudit)
        {
            await _next(context);
            return;
        }

        // Extract user info from claims
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "anonymous";
        var workspaceId = context.User.FindFirst("workspace_id")?.Value ?? "none";
        var email = context.User.FindFirst(ClaimTypes.Email)?.Value ?? "unknown";

        // Log before execution
        _logger.LogInformation(
            "Audit: User {UserId} (Workspace: {WorkspaceId}, Email: {Email}) performing {Method} on {Path}",
            userId,
            workspaceId,
            email,
            context.Request.Method,
            path);

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        await _next(context);

        stopwatch.Stop();

        // Log after execution with result
        var statusCode = context.Response.StatusCode;
        var success = statusCode >= 200 && statusCode < 300;

        if (success)
        {
            _logger.LogInformation(
                "Audit: User {UserId} completed {Method} on {Path} with status {StatusCode} in {ElapsedMs}ms",
                userId,
                context.Request.Method,
                path,
                statusCode,
                stopwatch.ElapsedMilliseconds);
        }
        else
        {
            _logger.LogWarning(
                "Audit: User {UserId} failed {Method} on {Path} with status {StatusCode} in {ElapsedMs}ms",
                userId,
                context.Request.Method,
                path,
                statusCode,
                stopwatch.ElapsedMilliseconds);
        }
    }
}

/// <summary>
/// Extension methods for registering audit logging middleware.
/// </summary>
public static class AuditLoggingMiddlewareExtensions
{
    public static IApplicationBuilder UseAuditLogging(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<AuditLoggingMiddleware>();
    }
}
