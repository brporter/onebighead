using OneBigHead.Server.Models;
namespace OneBigHead.Server.Authentication;

public class OidcProviderSettings
{
    public OidcProvider Microsoft { get; set; } = new();
    public OidcProvider Google { get; set; } = new();
    public OidcProvider Apple { get; set; } = new();
    public OidcProvider Get(IdentityProvider provider) => provider switch
    {
        IdentityProvider.Microsoft => Microsoft,
        IdentityProvider.Google => Google,
        IdentityProvider.Apple => Apple,
        _ => throw new ArgumentOutOfRangeException(nameof(provider))
    };
}