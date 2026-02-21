namespace OneBigHead.Server.Middleware;

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