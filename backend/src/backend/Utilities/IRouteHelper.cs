namespace OneBigHead.Server.Utilities;

public interface IRouteHelper 
{
    /// <summary>
    /// Determines if the given request path matches the specified route template.
    /// Caches compiled template matchers for performance on repeated checks.
    /// </summary>
    /// <param name="routeTemplate">The route template to match against (e.g., "/api/items/{id}").</param>
    /// <param name="requestPath">The incoming request path (e.g., "/api/items/123").</param>
    /// <returns>True if the request path matches the route template; otherwise, false.</returns>
    bool IsMatch(string routeTemplate, string requestPath);
}