using Microsoft.AspNetCore.Mvc.Rendering;

namespace OneBigHead.Server.Pages;

internal static class DevelopmentSignIn
{
    public static Task RenderAsync(IHtmlHelper html, SignInModel model)
    {
#if DEBUG
        return html.RenderPartialAsync("_DevelopmentSignIn", model);
#else
        return Task.CompletedTask;
#endif
    }
}
