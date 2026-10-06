using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Validators;
using OneBigHead.Server.Extensions;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Authentication;

public static class ExternalAuthenticationExtensions
{
    public static AuthenticationBuilder AddExternalProviders(this AuthenticationBuilder builder, AuthenticationSettings settings)
    {
        foreach (var provider in new[] { IdentityProvider.Google, IdentityProvider.Microsoft, IdentityProvider.Apple })
        {
            var configuration = settings.Providers.Get(provider);
            if (!configuration.IsConfigured) continue;
            builder.AddOpenIdConnect(provider.ToString(), options =>
            {
                options.Authority = configuration.Authority;
                options.ClientId = configuration.ClientId;
                options.ClientSecret = configuration.ClientSecret;
                options.CallbackPath = $"{settings.OAuth.CallbackPath}/{provider.ToString().ToLowerInvariant()}";
                options.SignInScheme = CookieJwtAuthenticationExtensions.SchemeName;
                options.MapInboundClaims = false;
                options.ResponseType = OpenIdConnectResponseType.Code;
                options.ResponseMode = provider == IdentityProvider.Apple ? OpenIdConnectResponseMode.FormPost : OpenIdConnectResponseMode.Query;
                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("email");
                options.Scope.Add(provider == IdentityProvider.Apple ? "name" : "profile");
                // Apple does not support PKCE. Other providers use the handler's default PKCE support.
                options.UsePkce = provider != IdentityProvider.Apple;
                if (provider == IdentityProvider.Microsoft)
                    options.TokenValidationParameters.IssuerValidator = AadIssuerValidator.GetAadIssuerValidator(configuration.Authority).Validate;

                options.Events = new OpenIdConnectEvents
                {
                    OnRedirectToIdentityProvider = context =>
                    {
                        // Keep the registered callback origin when running behind Vite or a reverse proxy.
                        if (!string.IsNullOrEmpty(settings.OAuth.BaseUrl))
                            context.ProtocolMessage.RedirectUri = settings.OAuth.BaseUrl.TrimEnd('/') + options.CallbackPath;
                        return Task.CompletedTask;
                    },
                    OnTicketReceived = async context =>
                    {
                        // TicketReceived runs after nonce, state and token checks have completed.
                        var email = context.Principal?.FindFirst("email")?.Value;
                        var subject = context.Principal?.FindFirst("sub")?.Value;
                        context.HandleResponse();
                        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(subject))
                        {
                            context.Response.Redirect(ErrorUrl(settings, "Email or subject claim missing"));
                            return;
                        }
                        var users = context.HttpContext.RequestServices.GetRequiredService<IExternalUserService>();
                        var (user, role) = await users.GetOrCreateAsync(provider,
                            new OidcValidationResult { IsValid = true, Email = email, Subject = subject });
                        if (user is null)
                        {
                            context.Response.Redirect(ErrorUrl(settings, "Failed to create user account"));
                            return;
                        }
                        var tokens = context.HttpContext.RequestServices.GetRequiredService<ITokenService>();
                        context.Response.SetAuthCookie(tokens.GenerateAppToken(user, role), settings);
                        context.Response.Redirect(context.ReturnUri ?? settings.OAuth.PostLoginRedirectUrl);
                    },
                    OnRemoteFailure = context =>
                    {
                        context.HandleResponse();
                        context.Response.Redirect(ErrorUrl(settings, "Authentication failed. Please try again."));
                        return Task.CompletedTask;
                    }
                };
            });
        }
        return builder;
    }

    private static string ErrorUrl(AuthenticationSettings settings, string message) =>
        $"{settings.OAuth.PostLoginErrorUrl}?error={Uri.EscapeDataString(message)}";
}
