using System.Security.Claims;
using OneBigHead.Server.Authentication;

namespace OneBigHead.Server.Tests.Authentication;

[Trait("Category", "Unit")]
public class ExternalIdentityClaimsTests
{
    [Fact]
    public void MissingPrincipalOrClaims_IsNotAnAccountIdentity()
    {
        Assert.False(ExternalIdentityClaims.Read(null).IsValid);
        Assert.False(ExternalIdentityClaims.Read(new ClaimsPrincipal(new ClaimsIdentity())).IsValid);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void RawAndMappedClaims_AreReadWithoutDependingOnMappingMode(bool rawEmail, bool rawSubject)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(rawEmail ? "email" : ClaimTypes.Email, "reader@example.test"),
            new Claim(rawSubject ? "sub" : ClaimTypes.NameIdentifier, "provider-subject")
        }));
        var result = ExternalIdentityClaims.Read(principal);
        Assert.True(result.IsValid);
        Assert.Equal("reader@example.test", result.Email);
        Assert.Equal("provider-subject", result.Subject);
    }

    [Fact]
    public void StandardClaims_TakePrecedenceOverMappedAliases()
    {
        var result = ExternalIdentityClaims.Read(new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim("email", "standard@example.test"), new Claim("sub", "standard-subject"),
            new Claim(ClaimTypes.Email, "alias@example.test"), new Claim(ClaimTypes.NameIdentifier, "alias-subject")
        })));
        Assert.Equal("standard@example.test", result.Email);
        Assert.Equal("standard-subject", result.Subject);
    }
}
