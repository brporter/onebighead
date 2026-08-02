using OneBigHead.Server.Authentication;
using OneBigHead.Server.Pages;
using Microsoft.Extensions.Options;

namespace OneBigHead.Server.Tests.Pages;

[Trait("Category", "Unit")]
public class SignInModelTests
{
    private static SignInModel CreateModel()
    {
        return new SignInModel(Options.Create(new AuthenticationSettings()));
    }

    [Fact]
    public void OnGet_NoParameters_HasNoErrorAndDefaultReturnUrl()
    {
        var model = CreateModel();

        model.OnGet();

        Assert.Null(model.ErrorMessage);
        Assert.Equal("/collections", model.ReturnUrl);
    }

    [Fact]
    public void OnGet_SessionRevokedErrorType_MapsToDisplayString()
    {
        var model = CreateModel();

        model.OnGet(errorType: AuthErrorType.SessionRevoked);

        Assert.Equal(AuthErrorMessages.GetMessage(AuthErrorType.SessionRevoked), model.ErrorMessage);
    }

    [Fact]
    public void OnGet_ErrorTypeTakesPrecedenceOverFreeTextError()
    {
        var model = CreateModel();

        model.OnGet(error: "oauth failure text", errorType: AuthErrorType.SessionRevoked);

        Assert.Equal(AuthErrorMessages.GetMessage(AuthErrorType.SessionRevoked), model.ErrorMessage);
    }

    [Fact]
    public void OnGet_NoneErrorType_FallsBackToFreeTextError()
    {
        var model = CreateModel();

        model.OnGet(error: "oauth failure text", errorType: AuthErrorType.None);

        Assert.Equal("oauth failure text", model.ErrorMessage);
    }

    [Fact]
    public void OnGet_ReturnUrlIsPreserved()
    {
        var model = CreateModel();

        model.OnGet(returnUrl: "/collections/5");

        Assert.Equal("/collections/5", model.ReturnUrl);
    }
}
