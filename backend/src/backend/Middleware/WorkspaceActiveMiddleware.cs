using System.Diagnostics;
using System.Security.Claims;
using System.Text.Json;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Services;
using OneBigHead.Server.Telemetry;
using OneBigHead.Server.Utilities;

namespace OneBigHead.Server.Middleware;

public readonly struct AllowedPathDefinition
{
    public string RouteTemplate { get; init; }
    public string Method { get; init; }
}

/// <summary>
/// Middleware that checks if the user and their current workspace are active.
/// Returns 401 Unauthorized with USER_DELETED code if user is soft-deleted or has no active workspaces.
/// Returns 410 Gone if the workspace is deleted, allowing the client to handle the situation.
/// </summary>
public class WorkspaceActiveMiddleware(RequestDelegate next, IRouteHelper routeHelper, ILogger<WorkspaceActiveMiddleware> logger)
{
    // Paths that should be accessible even when workspace is deleted
    private static readonly string[] ExcludedPrefixes =
    {
        "/api/auth",
        "/api/users/me/deletion-info",
        "/api/users/me/restorable-workspaces",
        "/api/themes",
        "/health"
    };

    private static readonly AllowedPathDefinition[] AllowedPaths =
    {
        new() { RouteTemplate = "/api/workspaces", Method = HttpMethod.Get.ToString() }, // List workspaces
        new() { RouteTemplate = "/api/workspaces", Method = HttpMethod.Post.ToString() }, // Create workspace
        new() { RouteTemplate = "/api/workspaces/{id}/switch", Method = HttpMethod.Post.ToString() }, // Switch workspace
        new() { RouteTemplate = "/api/workspaces/setup", Method = HttpMethod.Post.ToString() }, // Setup new workspace
        new() { RouteTemplate = "/api/workspaces/restore", Method = HttpMethod.Post.ToString() }, // Restore multiple workspaces
        new() { RouteTemplate = "/api/workspaces/{id}/restore", Method = HttpMethod.Post.ToString() } // Restore single workspace
    };

    public async Task InvokeAsync(HttpContext context, IWorkspaceService workspaceService)
    {
        using var activity = DiagnosticsConfig.AppActivitySource.StartActivity(nameof(WorkspaceActiveMiddleware), ActivityKind.Internal);
        var path = context.Request.Path.Value ?? "";

        // Skip excluded paths (auth endpoints, deletion info, health check, themes)
        if (ExcludedPrefixes.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
        {
            activity?.SetTag("workspace_check.outcome", "skipped");
            logger.LogDebug("Path {Path} matched excluded prefix, skipping workspace check", path);
            await next(context);
            return;
        }

        logger.LogDebug("Path {Path} did not match any excluded prefix", path);

        if (AllowedPaths.Any(apd =>
            {
                var isMatch = routeHelper.IsMatch(apd.RouteTemplate, path)
                              && string.Equals(context.Request.Method, apd.Method.ToString(),
                                  StringComparison.OrdinalIgnoreCase);

                if (isMatch)
                {
                    logger.LogDebug("Path {Path} with method {Method} matched allowed path template {Template}",
                        path, context.Request.Method, apd.RouteTemplate);
                }

                return isMatch;
            }))
        {
            await next(context);
            return;
        }

        // Get user ID from claims
        var userIdClaim = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!string.IsNullOrEmpty(userIdClaim) && int.TryParse(userIdClaim, out var userId))
        {
            // Check if user is soft-deleted
            var isUserDeleted = await workspaceService.IsUserDeletedAsync(userId);
            if (isUserDeleted)
            {
                activity?.SetTag("workspace_check.outcome", "user_deleted");
                activity?.SetTag("user_id", userId);

                logger.LogWarning("Request blocked for deleted user {UserId} at path {Path}",
                    userId, path);

                // TODO: throw a custom exception here and rely on the GlobalExceptionHandler to convert to an error response
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

            // Check if user has any active workspaces
            var hasActiveWorkspace = await workspaceService.HasUserAnyActiveWorkspaceAsync(userId);
            if (!hasActiveWorkspace)
            {
                activity?.SetTag("workspace_check.outcome", "no_active_workspaces");
                activity?.SetTag("user_id", userId);
                logger.LogWarning("Request blocked for user {UserId} with no active workspaces at path {Path}",
                    userId, path);

                // TODO: throw a custom exception here and rely on the GlobalExceptionHandler to convert to an error response
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";
                context.Response.Headers.CacheControl = "no-store";

                var response = new
                {
                    error = "You have no active workspaces. Please create or restore a workspace.",
                    code = "NO_ACTIVE_WORKSPACES"
                };

                await context.Response.WriteAsync(JsonSerializer.Serialize(response));
                return;
            }
        }

        // Get workspace ID from claims
        var workspaceIdClaim = context.User.FindFirst(ClaimNames.WorkspaceId)?.Value;
        if (string.IsNullOrEmpty(workspaceIdClaim) || !int.TryParse(workspaceIdClaim, out var workspaceId))
        {
            // No workspace in token, let the request proceed (will likely fail auth)
            await next(context);
            return;
        }

        // Check if workspace is deleted
        var isDeleted = await workspaceService.IsWorkspaceDeletedAsync(workspaceId);
        if (isDeleted)
        {
            activity?.SetTag("workspace_check.outcome", "workspace_deleted");
            activity?.SetTag("workspace_id", workspaceId);
            logger.LogWarning("Request blocked for deleted workspace {WorkspaceId} at path {Path}",
                workspaceId, path);

            // TODO: throw a custom exception here and rely on the GlobalExceptionHandler to convert to an error response
            context.Response.StatusCode = StatusCodes.Status410Gone;
            context.Response.ContentType = "application/json";
            // Prevent browsers from caching 410 responses - user may create/restore a workspace
            context.Response.Headers.CacheControl = "no-store";

            var response = new
            {
                error = "This organization has been deleted. Please switch to another organization or create a new one.",
                code = "WORKSPACE_DELETED"
            };

            await context.Response.WriteAsync(JsonSerializer.Serialize(response));
            return;
        }

        activity?.SetTag("workspace_check.outcome", "passed");
        activity?.SetTag("workspace_id", workspaceId);
        await next(context);
    }
}

/// <summary>
/// Extension methods for registering workspace active middleware.
/// </summary>
public static class WorkspaceActiveMiddlewareExtensions
{
    public static IApplicationBuilder UseWorkspaceActiveCheck(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<WorkspaceActiveMiddleware>();
    }
}
