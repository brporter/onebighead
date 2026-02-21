namespace OneBigHead.Server.Authentication;

public class OAuthSettings
{
    public string BaseUrl { get; set; } = string.Empty;
    public string CallbackPath { get; set; } = "/api/auth/callback";
    public string PostLoginRedirectUrl { get; set; } = "/collections";
    public string PostLoginErrorUrl { get; set; } = "/signin";
}