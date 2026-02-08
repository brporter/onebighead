using System.Diagnostics;
using System.Security.Claims;
using System.Text.Json;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Services;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Middleware;

/// <summary>
/// Middleware that checks if the user and their current workspace are active.
/// Returns 401 Unauthorized with USER_DELETED code if user is soft-deleted or has no active workspaces.
/// Returns 410 Gone if the workspace is deleted, allowing the client to handle the situation.
/// </summary>
public class WorkspaceActiveMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<WorkspaceActiveMiddleware> _logger;

    // Paths that should be accessible even when workspace is deleted
    private static readonly string[] ExcludedPrefixes =
    {
        "/api/auth",
        "/api/users/me/deletion-info",
        "/api/users/me/restorable-workspaces",
        "/api/themes",
        "/health"
    };

    // Paths that need workspace context but should be accessible (for workspace switching)
    private static readonly string[] WorkspaceManagementPaths =
    {
        "/api/workspaces"
    };

    public WorkspaceActiveMiddleware(RequestDelegate next, ILogger<WorkspaceActiveMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, IWorkspaceDeletionService workspaceDeletionService)
    {
        using var activity = DiagnosticsConfig.AppActivitySource.StartActivity("WorkspaceActiveCheck", ActivityKind.Internal);
        var path = context.Request.Path.Value ?? "";

        // Skip excluded paths (auth endpoints, deletion info, health check, themes)
        if (ExcludedPrefixes.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
        {
            activity?.SetTag("obh.workspace_check.outcome", "skipped");
            _logger.LogDebug("Path {Path} matched excluded prefix, skipping workspace check", path);
            await _next(context);
            return;
        }

        _logger.LogDebug("Path {Path} did not match any excluded prefix", path);

        // Allow workspace listing and switching (GET /api/workspaces, POST /api/workspaces/{id}/switch)
        if (path.StartsWith("/api/workspaces", StringComparison.OrdinalIgnoreCase))
        {
            // Allow GET /api/workspaces (list workspaces)
            if (path.Equals("/api/workspaces", StringComparison.OrdinalIgnoreCase) &&
                context.Request.Method == "GET")
            {
                await _next(context);
                return;
            }

            // Allow POST /api/workspaces/{id}/switch (switch workspace)
            if (path.EndsWith("/switch", StringComparison.OrdinalIgnoreCase) &&
                context.Request.Method == "POST")
            {
                await _next(context);
                return;
            }

            // Allow POST /api/workspaces (create new workspace)
            if (path.Equals("/api/workspaces", StringComparison.OrdinalIgnoreCase) &&
                context.Request.Method == "POST")
            {
                await _next(context);
                return;
            }

            // Allow POST /api/workspaces/setup (setup new workspace)
            if (path.Equals("/api/workspaces/setup", StringComparison.OrdinalIgnoreCase) &&
                context.Request.Method == "POST")
            {
                await _next(context);
                return;
            }

            // Allow POST /api/workspaces/restore (restore multiple workspaces)
            if (path.Equals("/api/workspaces/restore", StringComparison.OrdinalIgnoreCase) &&
                context.Request.Method == "POST")
            {
                await _next(context);
                return;
            }

            // Allow POST /api/workspaces/{id}/restore (restore single workspace)
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
            var isUserDeleted = await workspaceDeletionService.IsUserDeletedAsync(userId);
            if (isUserDeleted)
            {
                activity?.SetTag("obh.workspace_check.outcome", "user_deleted");
                activity?.SetTag("obh.user_id", userId);
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

            // Check if user has any active workspaces
            var hasActiveWorkspace = await workspaceDeletionService.HasUserAnyActiveWorkspaceAsync(userId);
            if (!hasActiveWorkspace)
            {
                activity?.SetTag("obh.workspace_check.outcome", "no_active_workspaces");
                activity?.SetTag("obh.user_id", userId);
                _logger.LogWarning("Request blocked for user {UserId} with no active workspaces at path {Path}",
                    userId, path);

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
            await _next(context);
            return;
        }

        // Check if workspace is deleted
        var isDeleted = await workspaceDeletionService.IsWorkspaceDeletedAsync(workspaceId);
        if (isDeleted)
        {
            activity?.SetTag("obh.workspace_check.outcome", "workspace_deleted");
            activity?.SetTag("obh.workspace_id", workspaceId);
            _logger.LogWarning("Request blocked for deleted workspace {WorkspaceId} at path {Path}",
                workspaceId, path);

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

        activity?.SetTag("obh.workspace_check.outcome", "passed");
        activity?.SetTag("obh.workspace_id", workspaceId);
        await _next(context);
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
