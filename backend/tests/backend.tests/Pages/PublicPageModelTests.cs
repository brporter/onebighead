using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OneBigHead.Server.Pages;

namespace OneBigHead.Server.Tests.Pages;

[Trait("Category", "Unit")]
public class PublicPageModelTests
{
    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("CookieJwt", true)]
    public void Home_UsesTheEstablishedAuthenticationResult(string? scheme, bool expected)
    {
        var context = new DefaultHttpContext
        {
            User = scheme is null ? new ClaimsPrincipal() : new ClaimsPrincipal(new ClaimsIdentity([], scheme))
        };
        var model = new IndexModel { PageContext = new PageContext { HttpContext = context } };
        Assert.Equal(expected, model.IsAuthenticated);
    }

    [Fact]
    public void ErrorPage_UsesTheActiveDiagnosticReference()
    {
        using var activity = new Activity("error-page-test").Start();
        var model = ErrorPage();
        model.OnGet();
        Assert.Equal(activity.Id, model.RequestId);
        Assert.True(model.ShowRequestId);
    }

    [Fact]
    public void ErrorPage_FallsBackToTheRequestReferenceWithoutAnActivity()
    {
        var previous = Activity.Current;
        try
        {
            Activity.Current = null;
            var model = ErrorPage();
            model.OnGet();
            Assert.Equal("request-reference", model.RequestId);
            Assert.True(model.ShowRequestId);
        }
        finally { Activity.Current = previous; }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ErrorPage_DoesNotOfferAnEmptyReference(string? reference)
    {
        Assert.False(new ErrorModel { RequestId = reference }.ShowRequestId);
    }

    private static ErrorModel ErrorPage() => new()
    {
        PageContext = new PageContext { HttpContext = new DefaultHttpContext { TraceIdentifier = "request-reference" } }
    };
}
