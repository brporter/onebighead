using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.Middleware;

namespace OneBigHead.Server.Hosting;

internal static class ApplicationServices
{
    public static IServiceCollection AddApplicationServices(this IServiceCollection services,
        IConfiguration configuration, IHostEnvironment environment)
    {
        services.AddControllers().AddJsonOptions(options =>
        {
            options.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
            options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
        });
        services.AddRazorPages();
        services.Configure<RouteOptions>(options => options.LowercaseUrls = true);
        services.AddOpenApi();
        services.AddExceptionHandler<GlobalExceptionHandler>();
        services.AddProblemDetails();
        services.AddSingleton<SpaAssets>();

        // HTTP tests supply their own database. Every other environment uses the same provider.
        if (!environment.IsEnvironment("Testing"))
        {
            services.AddDbContextFactory<AppDbContext>(options =>
                options.UseNpgsql(configuration.GetConnectionString("DefaultConnection")));
        }

        services.AddApplicationDependencies(configuration);
        services.AddApplicationAuthentication(configuration);
        services.AddEndpointRateLimits();
        return services;
    }
}
