using System.Diagnostics;

namespace OneBigHead.Server.Telemetry;

public static class TracingServiceCollectionExtensions
{
    /// <summary>
    /// Registers TImpl as a scoped service, then registers TInterface as a scoped factory
    /// that wraps TImpl in its generated TracingProxy_{TInterface} decorator.
    /// </summary>
    public static IServiceCollection AddTracingDecorator<TInterface, TImpl>(
        this IServiceCollection services, ActivitySource activitySource)
        where TInterface : class
        where TImpl : class, TInterface
    {
        services.AddScoped<TImpl>();
        services.AddScoped<TInterface>(sp =>
        {
            var inner = sp.GetRequiredService<TImpl>();
            var proxyTypeName = $"{typeof(TInterface).Namespace}.TracingProxy_{typeof(TInterface).Name}";
            var proxyType = typeof(TInterface).Assembly.GetType(proxyTypeName);

            if (proxyType is null)
            {
                // Fallback: no generated proxy found, use inner directly
                return inner;
            }

            return (TInterface)Activator.CreateInstance(proxyType, inner, activitySource)!;
        });

        return services;
    }
}
