using OneBigHead.Server.Authentication;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace OneBigHead.Server.Pages;

public class SignInModel : PageModel
{
    private readonly AuthenticationSettings _authSettings;

    public SignInModel(IOptions<AuthenticationSettings> authSettings)
    {
        _authSettings = authSettings.Value;
    }

    public bool MicrosoftEnabled => _authSettings.Providers.Microsoft.Enabled;
    public bool GoogleEnabled => _authSettings.Providers.Google.Enabled;
    public bool AppleEnabled => _authSettings.Providers.Apple.Enabled;
    
    public string? ErrorMessage { get; set; }
    public string? ReturnUrl { get; set; }

    public void OnGet(string? error = null, string? returnUrl = null, AuthErrorType errorType = AuthErrorType.None)
    {
        // A typed error code takes precedence over free-text error messages
        // (used by the OAuth flow) and is mapped to its display string here.
        ErrorMessage = AuthErrorMessages.GetMessage(errorType) ?? error;
        ReturnUrl = returnUrl ?? "/collections";
    }
}

