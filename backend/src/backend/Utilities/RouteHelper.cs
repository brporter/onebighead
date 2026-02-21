using System.Collections.Concurrent;
using Microsoft.AspNetCore.Routing.Template;

namespace OneBigHead.Server.Utilities;

public class RouteHelper
    : IRouteHelper
{
    private readonly ConcurrentDictionary<string, bool> _matchHistory = new();

    public bool IsMatch(string routeTemplate, string requestPath)
    {
        if (_matchHistory.TryGetValue(routeTemplate, out var match))
            return match;

        var template = TemplateParser.Parse(routeTemplate);
        var matcher = new TemplateMatcher(template, new RouteValueDictionary());
        var isMatch = matcher.TryMatch(requestPath, new RouteValueDictionary());
        
        _matchHistory.AddOrUpdate(
            routeTemplate, 
            isMatch, 
            (key, oldValue) => oldValue);

        return _matchHistory[routeTemplate];
    }
}