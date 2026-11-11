using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Moq;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services.Accounts;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class AccountControllerTests
{
    private readonly Mock<IAccountDeletionReader> reader = new();
    private readonly Mock<IAccountDeletion> deletion = new();

    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    [InlineData("0")]
    [InlineData("-1")]
    public async Task InvalidIdentity_DoesNotReadOrDelete(string? id)
    {
        var controller = Create(id);
        Assert.IsType<UnauthorizedResult>((await controller.GetDeletionInfo()).Result);
        Assert.IsType<UnauthorizedResult>((await controller.DeleteAccount(new())).Result);
        reader.VerifyNoOtherCalls();
        deletion.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Preview_ReturnsCurrentAccountOrNotFound()
    {
        var controller = Create("7");
        Assert.IsType<NotFoundObjectResult>((await controller.GetDeletionInfo()).Result);
        var info = new UserDeletionInfoResponse { UserId = 7 };
        reader.Setup(r => r.ReadAsync(7)).ReturnsAsync(info);
        Assert.Same(info, Assert.IsType<OkObjectResult>((await controller.GetDeletionInfo()).Result).Value);
    }

    [Theory]
    [InlineData(AccountDeletionStatus.Deleted, 200)]
    [InlineData(AccountDeletionStatus.Invalid, 400)]
    [InlineData(AccountDeletionStatus.Conflict, 409)]
    public async Task Delete_MapsOutcomeAndClearsCookieOnlyAfterSuccess(AccountDeletionStatus status, int code)
    {
        var request = new DeleteUserRequest { ConfirmEmail = "owner@example.test" };
        var error = status == AccountDeletionStatus.Deleted ? null : "Review your choices";
        deletion.Setup(d => d.DeleteAsync(7, request)).ReturnsAsync(new AccountDeletionResult(status, error));
        var controller = Create("7");
        var result = Assert.IsAssignableFrom<ObjectResult>((await controller.DeleteAccount(request)).Result);
        Assert.Equal(code, result.StatusCode);
        var body = Assert.IsType<DeleteUserResponse>(result.Value);
        Assert.Equal(status == AccountDeletionStatus.Deleted, body.Success);
        Assert.Equal(error, body.Error);
        Assert.Equal(status == AccountDeletionStatus.Deleted, controller.Response.Headers.ContainsKey("Set-Cookie"));
        deletion.Verify(d => d.DeleteAsync(7, request), Times.Once);
    }

    private AccountController Create(string? id) => new(reader.Object, deletion.Object, Options.Create(new AuthenticationSettings()))
    {
        ControllerContext = new() { HttpContext = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(id is null ? [] : [new Claim(ClaimTypes.NameIdentifier, id)], "Test"))
        } }
    };
}
