using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Moq;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Services.Administration;

namespace OneBigHead.Server.Tests.Authentication;

[Trait("Category", "Unit")]
public class SystemAdministratorAuthorizationHandlerTests
{
    [Theory]
    [InlineData(null, null)]
    [InlineData("1", null)]
    [InlineData(null, "Test")]
    [InlineData("invalid", "Test")]
    [InlineData("0", "Test")]
    [InlineData("-1", "Test")]
    public async Task InvalidIdentities_DoNotQueryOrGrantAccess(string? userId, string? authenticationType)
    {
        var claims = userId is null ? Array.Empty<Claim>() : [new Claim(ClaimTypes.NameIdentifier, userId)];
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType));
        var access = new Mock<IAdministratorAccessService>(MockBehavior.Strict);
        var requirement = new SystemAdministratorRequirement();
        var context = new AuthorizationHandlerContext([requirement], principal, null);
        await new SystemAdministratorAuthorizationHandler(access.Object).HandleAsync(context);
        Assert.False(context.HasSucceeded);
        access.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task MissingIdentity_DoesNotGrantAccess()
    {
        var context = new AuthorizationHandlerContext([new SystemAdministratorRequirement()], new ClaimsPrincipal(), null);
        await new SystemAdministratorAuthorizationHandler(Mock.Of<IAdministratorAccessService>()).HandleAsync(context);
        Assert.False(context.HasSucceeded);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task CurrentAccountDeterminesAccess_RegardlessOfStaleTokenRole(bool currentAdmin, bool tokenAdmin)
    {
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, "7") };
        if (tokenAdmin) claims.Add(new(ClaimTypes.Role, "SystemAdministrator"));
        var access = new Mock<IAdministratorAccessService>();
        access.Setup(service => service.HasAccessAsync(7)).ReturnsAsync(currentAdmin);
        var requirement = new SystemAdministratorRequirement();
        var context = new AuthorizationHandlerContext([requirement], new ClaimsPrincipal(new ClaimsIdentity(claims, "Test")), null);
        await new SystemAdministratorAuthorizationHandler(access.Object).HandleAsync(context);
        Assert.Equal(currentAdmin, context.HasSucceeded);
        access.Verify(service => service.HasAccessAsync(7), Times.Once);
    }

    [Fact]
    public async Task FailedAccountRead_CannotGrantAccess()
    {
        var error = new InvalidOperationException("Database unavailable");
        var access = new Mock<IAdministratorAccessService>();
        access.Setup(service => service.HasAccessAsync(7)).ThrowsAsync(error);
        var context = new AuthorizationHandlerContext([new SystemAdministratorRequirement()],
            new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "7"), new Claim(ClaimTypes.Role, "SystemAdministrator")], "Test")), null);
        Assert.Same(error, await Assert.ThrowsAsync<InvalidOperationException>(() => new SystemAdministratorAuthorizationHandler(access.Object).HandleAsync(context)));
        Assert.False(context.HasSucceeded);
    }
}
