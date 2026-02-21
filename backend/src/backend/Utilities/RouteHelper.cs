using System.Collections.Concurrent;
using Microsoft.AspNetCore.Routing.Template;

namespace OneBigHead.Server.Utilities;

public class RouteHelper
    : IRouteHelper
{
    private readonly ConcurrentDictionary<string, TemplateMatcher> _matchers = new();

    public bool IsMatch(string routeTemplate, string requestPath)
    {
        var matcher = _matchers.GetOrAdd(
            routeTemplate,
            key =>
            {
                var template = TemplateParser.Parse(key);
                return new TemplateMatcher(template, new RouteValueDictionary());
            });

        return matcher.TryMatch(requestPath, new RouteValueDictionary());
    }
}