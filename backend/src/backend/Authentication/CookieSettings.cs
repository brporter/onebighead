namespace OneBigHead.Server.Authentication;

public class CookieSettings
{
    public string Name { get; set; } = "auth_token";
    public bool Secure { get; set; } = true;
    public string SameSite { get; set; } = "Strict";
}