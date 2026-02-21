namespace OneBigHead.Server.Authentication;

public class OidcValidationResult
{
    public bool IsValid { get; set; }
    public string? Email { get; set; }
    public string? Subject { get; set; }
    public string? Error { get; set; }
}