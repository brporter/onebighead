namespace OneBigHead.Server.Authentication;

public class OidcProviderSettings
{
    public OidcProvider Microsoft { get; set; } = new();
    public OidcProvider Google { get; set; } = new();
    public OidcProvider Apple { get; set; } = new();
}