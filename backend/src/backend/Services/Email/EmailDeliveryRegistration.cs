using Azure.Communication.Email;
using Microsoft.Extensions.Options;

namespace OneBigHead.Server.Services.Email;

public static class EmailDeliveryRegistration
{
    public static IServiceCollection AddEmailDelivery(this IServiceCollection services)
    {
        services.AddSingleton(provider => new EmailClient(provider.GetRequiredService<IOptions<EmailSettings>>().Value.ConnectionString));
        services.AddSingleton<AzureEmailDelivery>();
        services.AddSingleton<DisabledEmailDelivery>();
        services.AddSingleton<IEmailDelivery>(provider =>
            string.IsNullOrWhiteSpace(provider.GetRequiredService<IOptions<EmailSettings>>().Value.ConnectionString)
                ? provider.GetRequiredService<DisabledEmailDelivery>()
                : provider.GetRequiredService<AzureEmailDelivery>());
        return services;
    }
}
