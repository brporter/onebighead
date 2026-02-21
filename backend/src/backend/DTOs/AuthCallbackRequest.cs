namespace OneBigHead.Server.DTOs;

public class AuthCallbackRequest
{
    public string Token { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty;
}