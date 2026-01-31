using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using OneBigHead.Server.Authentication;

namespace OneBigHead.Server.Pages;

public class IndexModel : PageModel
{
    private readonly ITokenService _tokenService;
    private readonly AuthenticationSettings _authSettings;

    public IndexModel(ITokenService tokenService, IOptions<AuthenticationSettings> authSettings)
    {
        _tokenService = tokenService;
        _authSettings = authSettings.Value;
    }

    public bool IsAuthenticated { get; private set; }

    public void OnGet()
    {
        var token = Request.Cookies[_authSettings.Cookie.Name];
        if (!string.IsNullOrEmpty(token))
        {
            var principal = _tokenService.ValidateAppToken(token);
            IsAuthenticated = principal != null;
        }
    }
}
