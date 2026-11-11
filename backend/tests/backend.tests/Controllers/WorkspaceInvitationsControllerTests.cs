using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Moq;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Invitations;

namespace OneBigHead.Server.Tests.Controllers;

public class WorkspaceInvitationsControllerTests
{
    private readonly Mock<IInvitationDirectory> _directory = new(MockBehavior.Strict);
    private readonly Mock<IInvitationCancellation> _cancellation = new(MockBehavior.Strict);
    private readonly Mock<IInvitationPreview> _preview = new(MockBehavior.Strict);
    private readonly Mock<IInvitationAcceptance> _acceptance = new(MockBehavior.Strict);
    private readonly Mock<ITokenService> _tokens = new(MockBehavior.Strict);

    [Theory]
    [InlineData(null, "2")]
    [InlineData("bad", "2")]
    [InlineData("0", "2")]
    [InlineData("1", null)]
    [InlineData("1", "0")]
    public async Task AdministrativeActions_RejectInvalidClaims(string? user, string? workspace)
    {
        var controller = Controller(user, workspace);
        Assert.IsType<UnauthorizedResult>(await controller.List());
        Assert.IsType<UnauthorizedResult>(await controller.Cancel(Guid.NewGuid()));
        _directory.VerifyNoOtherCalls();
        _cancellation.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("0")]
    public async Task Acceptance_RejectsInvalidIdentityBeforeReadingTheLink(string? user)
    {
        Assert.IsType<UnauthorizedResult>(await AccessController(user).Accept(new()));
        _acceptance.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Directory_MapsCurrentAccessWithoutCaching(bool allowed)
    {
        IReadOnlyList<WorkspaceInvitationResponse>? invitations = allowed ? [] : null;
        _directory.Setup(port => port.ReadAsync(1, 2)).ReturnsAsync(invitations);
        var controller = Controller();
        var result = await controller.List();
        if (allowed) Assert.Same(invitations, Assert.IsType<OkObjectResult>(result).Value);
        else Assert.IsType<ForbidResult>(result);
        Assert.Equal("no-store", controller.Response.Headers.CacheControl);
    }

    [Theory]
    [InlineData(InvitationCancellationStatus.Cancelled, typeof(NoContentResult))]
    [InlineData(InvitationCancellationStatus.Forbidden, typeof(ForbidResult))]
    [InlineData(InvitationCancellationStatus.NotFound, typeof(NotFoundResult))]
    [InlineData(InvitationCancellationStatus.Conflict, typeof(ConflictObjectResult))]
    public async Task Cancellation_MapsResult(InvitationCancellationStatus status, Type expected)
    {
        var id = Guid.NewGuid();
        _cancellation.Setup(port => port.CancelAsync(1, 2, id)).ReturnsAsync(status);
        Assert.IsType(expected, await Controller().Cancel(id));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Preview_ForwardsCancellationAndReturnsOnlyAvailableInvitations(bool available)
    {
        using var token = new CancellationTokenSource();
        var request = new InvitationAccessRequest();
        var preview = available ? new InvitationPreviewResponse("Workspace", "email@example.test", WorkspaceRole.Normal, DateTime.UtcNow) : null;
        _preview.Setup(port => port.ReadAsync(request, token.Token)).ReturnsAsync(preview);
        var controller = AccessController();
        controller.HttpContext.RequestAborted = token.Token;
        var result = await controller.Preview(request);
        if (available) Assert.Same(preview, Assert.IsType<OkObjectResult>(result).Value);
        else Assert.IsType<NotFoundObjectResult>(result);
        Assert.Equal("no-store", controller.Response.Headers.CacheControl);
    }

    [Theory]
    [InlineData(InvitationAcceptanceStatus.Joined, typeof(OkObjectResult))]
    [InlineData(InvitationAcceptanceStatus.Invalid, typeof(NotFoundObjectResult))]
    [InlineData(InvitationAcceptanceStatus.Unauthenticated, typeof(UnauthorizedResult))]
    [InlineData(InvitationAcceptanceStatus.Conflict, typeof(ConflictObjectResult))]
    public async Task Acceptance_IssuesACookieOnlyForTheCommittedSession(InvitationAcceptanceStatus status, Type expected)
    {
        var request = new InvitationAccessRequest();
        using var token = new CancellationTokenSource();
        var session = CurrentUserSession.FromUser(new User { Id = 1 });
        _acceptance.Setup(port => port.AcceptAsync(1, request, token.Token)).ReturnsAsync(new InvitationAcceptanceResult(status, session));
        if (status == InvitationAcceptanceStatus.Joined) _tokens.Setup(port => port.GenerateAppToken(session.User, session.Response.WorkspaceRole)).Returns("signed");
        var controller = AccessController();
        controller.HttpContext.RequestAborted = token.Token;
        Assert.IsType(expected, await controller.Accept(request));
        Assert.Equal(status == InvitationAcceptanceStatus.Joined, controller.Response.Headers.ContainsKey("Set-Cookie"));
        Assert.Equal("no-store", controller.Response.Headers.CacheControl);
        _acceptance.VerifyAll();
        _tokens.VerifyAll();
    }

    private WorkspaceInvitationsController Controller(string? user = "1", string? workspace = "2")
    {
        var claims = new List<Claim>();
        if (user is not null) claims.Add(new(ClaimTypes.NameIdentifier, user));
        if (workspace is not null) claims.Add(new(ClaimNames.WorkspaceId, workspace));
        return new(_directory.Object, _cancellation.Object)
        {
            ControllerContext = new() { HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Test")) } }
        };
    }
    private InvitationAccessController AccessController(string? user = "1") =>
        new(_preview.Object, _acceptance.Object, _tokens.Object, Options.Create(new AuthenticationSettings()))
        { ControllerContext = Controller(user, null).ControllerContext };
}
