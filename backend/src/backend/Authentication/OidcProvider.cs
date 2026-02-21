namespace OneBigHead.Server.Authentication;

public class OidcProvider
{
    public string Authority { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public bool Enabled { get; set; }
}