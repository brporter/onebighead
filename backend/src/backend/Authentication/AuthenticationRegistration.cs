using Microsoft.AspNetCore.Authorization;
using OneBigHead.Server.Services.Administration;

namespace OneBigHead.Server.Authentication;

internal static class AuthenticationRegistration
{
    public static IServiceCollection AddApplicationAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        // Configure authentication
        services.Configure<AuthenticationSettings>(configuration.GetSection("Authentication"));
        services.AddSingleton<ITokenService, TokenService>();
        services.AddMemoryCache();
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<ITokenRevocationService, TokenRevocationService>();
        services.AddSingleton<IAccountSessionValidator, AccountSessionValidator>();
        services.AddSingleton<IOidcTokenValidator, OidcTokenValidator>();
        services.AddSingleton<IExternalUserService, ExternalUserService>();
        services.AddSingleton<ICurrentUserSessionReader, CurrentUserSessionReader>();
        services.AddHttpClient();
        services.AddSingleton<IAuthorizationHandler, SystemAdministratorAuthorizationHandler>();

        services.AddAuthentication(CookieJwtAuthenticationExtensions.SchemeName)
            .AddCookieJwtAuthentication()
            .AddExternalProviders(configuration.GetSection("Authentication").Get<AuthenticationSettings>() ?? new());

        services.AddAuthorization(options =>
        {
            options.AddPolicy(SystemAdministratorRequirement.PolicyName, policy =>
                policy.RequireAuthenticatedUser().AddRequirements(new SystemAdministratorRequirement()));
            options.AddPolicy("WorkspaceAdmin", policy =>
                policy.RequireClaim("workspace_role", "WorkspaceAdmin"));
        });

        return services;
    }
}
