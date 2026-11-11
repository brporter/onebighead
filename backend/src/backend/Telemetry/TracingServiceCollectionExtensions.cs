using System.Diagnostics;

namespace OneBigHead.Server.Telemetry;

public static class TracingServiceCollectionExtensions
{
    /// <summary>
    /// Registers TImpl as a singleton service, then registers TInterface as a singleton factory
    /// that wraps TImpl in its generated TracingProxy_{TInterface} decorator.
    /// Without a generated decorator, registers only TInterface with TImpl as its implementation.
    /// </summary>
    public static IServiceCollection AddTracingDecorator<TInterface, TImpl>(
        this IServiceCollection services, ActivitySource activitySource)
        where TInterface : class
        where TImpl : class, TInterface
    {
        var prefix = typeof(TInterface).Namespace is { } ns ? $"{ns}." : string.Empty;
        var proxyTypeName = $"{prefix}TracingProxy_{typeof(TInterface).Name}";
        var proxyType = typeof(TInterface).Assembly.GetType(proxyTypeName);
        if (proxyType is null)
        {
            // A factory alias would give the container two disposal registrations
            // for the same implementation. The fallback has one owner instead.
            return services.AddSingleton<TInterface, TImpl>();
        }

        services.AddSingleton<TImpl>();
        services.AddSingleton<TInterface>(sp =>
        {
            var inner = sp.GetRequiredService<TImpl>();
            return (TInterface)Activator.CreateInstance(proxyType, inner, activitySource)!;
        });

        return services;
    }
}
