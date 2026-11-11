using Microsoft.AspNetCore.Mvc.RazorPages;

namespace OneBigHead.Server.Pages;

public class IndexModel : PageModel
{
    // Use the authentication pipeline, including revocation, rather than
    // validating the cookie independently and bypassing its policy.
    public bool IsAuthenticated => User.Identity?.IsAuthenticated == true;
}
