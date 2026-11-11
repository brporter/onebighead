using OneBigHead.Server.DTOs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.Services.Publishing;
using System.Security.Claims;

namespace backend.tests.Controllers;

[Trait("Category", "Unit")]
public class PublishManagerControllerTests
{
    private const int TestWorkspaceId = 1;
    private const int TestUserId = 100;

    private readonly Mock<IPublicationService> _mockService = new();
    private readonly PublishManagerController _controller;

    public PublishManagerControllerTests()
    {
        _controller = new PublishManagerController(_mockService.Object);
        SetupAuth(TestWorkspaceId, TestUserId);
    }

    private void SetupAuth(int workspaceId, int userId)
    {
        var claims = new[]
        {
            new Claim("workspace_id", workspaceId.ToString()),
            new Claim("sub", userId.ToString()),
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Email, "test@example.com"),
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = principal }
        };
    }

    [Fact]
    public async Task Preflight_ReturnsOkWithPreflightResponse()
    {
        var request = new PreflightRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } }
        };

        _mockService.Setup(s => s.PreflightAsync(TestWorkspaceId, request, default))
            .ReturnsAsync(PublicationResult<PreflightResponse>.Success(new() { Ready = true }));

        var result = await _controller.Preflight(TestWorkspaceId, request);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PreflightResponse>(ok.Value);
        Assert.True(response.Ready);
    }

    [Fact]
    public async Task Preflight_WrongWorkspace_ReturnsForbid()
    {
        var request = new PreflightRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } }
        };

        var result = await _controller.Preflight(999, request);

        Assert.IsType<ForbidResult>(result);
    }

    [Fact]
    public async Task Execute_ReturnsOkWithExecuteResponse()
    {
        var request = new ExecuteRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } },
            Resolutions = new List<PublishResolution>()
        };

        _mockService.Setup(s => s.ExecuteAsync(TestWorkspaceId, request, default))
            .ReturnsAsync(PublicationResult<ExecuteResponse>.Success(new() { Success = true }));

        var result = await _controller.Execute(TestWorkspaceId, request);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<ExecuteResponse>(ok.Value);
        Assert.True(response.Success);
    }

    [Fact]
    public async Task Execute_WrongWorkspace_ReturnsForbid()
    {
        var request = new ExecuteRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } },
            Resolutions = new List<PublishResolution>()
        };

        var result = await _controller.Execute(999, request);

        Assert.IsType<ForbidResult>(result);
    }

    [Theory]
    [InlineData(PublicationFailure.Invalid, 400)]
    [InlineData(PublicationFailure.NotFound, 404)]
    [InlineData(PublicationFailure.Conflict, 409)]
    public async Task Failures_MapToConsistentHttpResults(PublicationFailure failure, int status)
    {
        var preflight = new PreflightRequest { Entities = [] };
        var execute = new ExecuteRequest { Entities = [] };
        var error = new PublicationError(failure, "Rejected");
        _mockService.Setup(service => service.PreflightAsync(1, preflight, default)).ReturnsAsync(PublicationResult<PreflightResponse>.Failure(error));
        _mockService.Setup(service => service.ExecuteAsync(1, execute, default)).ReturnsAsync(PublicationResult<ExecuteResponse>.Failure(error));
        Assert.Equal(status, Assert.IsAssignableFrom<ObjectResult>(await _controller.Preflight(1, preflight)).StatusCode);
        Assert.Equal(status, Assert.IsAssignableFrom<ObjectResult>(await _controller.Execute(1, execute)).StatusCode);
    }

    [Fact]
    public async Task Actions_ForwardCancellationAndDoNotMaskUnknownFailures()
    {
        var token = new CancellationToken(true);
        var preflight = new PreflightRequest { Entities = [] };
        var execute = new ExecuteRequest { Entities = [] };
        _mockService.Setup(service => service.PreflightAsync(1, preflight, token)).ReturnsAsync(PublicationResult<PreflightResponse>.Success(new()));
        _mockService.Setup(service => service.ExecuteAsync(1, execute, token)).ReturnsAsync(PublicationResult<ExecuteResponse>.Success(new()));
        Assert.IsType<OkObjectResult>(await _controller.Preflight(1, preflight, token));
        Assert.IsType<OkObjectResult>(await _controller.Execute(1, execute, token));
        _mockService.VerifyAll();
        _mockService.Setup(service => service.PreflightAsync(1, preflight, default)).ReturnsAsync(PublicationResult<PreflightResponse>.Failure(new((PublicationFailure)999, "Invalid contract")));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => _controller.Preflight(1, preflight));
    }
}
