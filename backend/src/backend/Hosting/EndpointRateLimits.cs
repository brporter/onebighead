using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

namespace OneBigHead.Server.Hosting;

internal static class EndpointRateLimits
{
    public static IServiceCollection AddEndpointRateLimits(this IServiceCollection services)
    {
        // Configure rate limiting for auth endpoints
        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            // Fixed window limiter for login endpoints: 10 requests per minute per IP
            options.AddPolicy("auth-login", httpContext =>
                RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: ClientKey(httpContext),
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 10,
                        Window = TimeSpan.FromMinutes(1),
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        QueueLimit = 0
                    }));

            // Sliding window limiter for callback endpoints: 20 requests per minute per IP
            options.AddPolicy("auth-callback", context => SlidingWindow(context, 20));

            // Sliding window limiter for public endpoints: 60 requests per minute per IP
            options.AddPolicy("public-read", context => SlidingWindow(context, 60));
        });

        return services;
    }

    private static string ClientKey(HttpContext context)
        => context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    private static RateLimitPartition<string> SlidingWindow(HttpContext context, int limit)
        => RateLimitPartition.GetSlidingWindowLimiter(ClientKey(context), _ => new SlidingWindowRateLimiterOptions
        {
            PermitLimit = limit,
            Window = TimeSpan.FromMinutes(1),
            SegmentsPerWindow = 4,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = 0
        });
}
