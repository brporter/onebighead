using OneBigHead.Server.Services.Support;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Security.Claims;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class AdminSupportControllerTests
{
    private readonly Mock<ISupportRepository> _mockSupportRepository;
    private readonly Mock<ISupportReplies> _replies = new(MockBehavior.Strict);
    private readonly AdminSupportController _controller;

    public AdminSupportControllerTests()
    {
        _mockSupportRepository = new Mock<ISupportRepository>();
        _controller = new AdminSupportController(
            _mockSupportRepository.Object,
            _replies.Object
        );

        SetupAdminUser(1, "admin@example.com");
    }

    private void SetupAdminUser(int userId, string email)
    {
        var claims = new List<Claim>
        {
            new("workspace_id", "1"),
            new("sub", userId.ToString()),
            new(ClaimTypes.NameIdentifier, userId.ToString()),
            new(ClaimTypes.Email, email),
            new(ClaimTypes.Role, "SystemAdministrator")
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var claimsPrincipal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = claimsPrincipal }
        };
    }

    #region UpdateStatus Tests

    [Fact]
    public async Task UpdateStatus_UpdatesStatus_WhenRequestExists()
    {
        // Arrange
        var updatedRequest = new SupportRequest
        {
            Id = 1,
            UserId = 1,
            Email = "user@example.com",
            Subject = "Test Subject",
            Description = "Test Description",
            Status = SupportRequestStatus.InProgress,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            Replies = new List<SupportReply>()
        };

        _mockSupportRepository.Setup(r => r.UpdateStatusAsync(1, SupportRequestStatus.InProgress))
            .ReturnsAsync(updatedRequest);

        var dto = new UpdateSupportStatusDto { Status = SupportRequestStatus.InProgress };

        // Act
        var result = await _controller.UpdateStatus(1, dto);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedDto = Assert.IsType<SupportRequestDto>(okResult.Value);
        Assert.Equal("InProgress", returnedDto.Status);
    }

    [Fact]
    public async Task UpdateStatus_ReturnsNotFound_WhenRequestDoesNotExist()
    {
        // Arrange
        _mockSupportRepository.Setup(r => r.UpdateStatusAsync(999, It.IsAny<SupportRequestStatus>()))
            .ReturnsAsync((SupportRequest?)null);

        var dto = new UpdateSupportStatusDto { Status = SupportRequestStatus.Closed };

        // Act
        var result = await _controller.UpdateStatus(999, dto);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    [Theory]
    [InlineData(SupportRequestStatus.Open)]
    [InlineData(SupportRequestStatus.InProgress)]
    [InlineData(SupportRequestStatus.Resolved)]
    [InlineData(SupportRequestStatus.Closed)]
    public async Task UpdateStatus_HandlesAllStatusValues(SupportRequestStatus status)
    {
        // Arrange
        var updatedRequest = new SupportRequest
        {
            Id = 1,
            UserId = 1,
            Email = "user@example.com",
            Subject = "Test Subject",
            Description = "Test Description",
            Status = status,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            Replies = new List<SupportReply>()
        };

        _mockSupportRepository.Setup(r => r.UpdateStatusAsync(1, status))
            .ReturnsAsync(updatedRequest);

        var dto = new UpdateSupportStatusDto { Status = status };

        // Act
        var result = await _controller.UpdateStatus(1, dto);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedDto = Assert.IsType<SupportRequestDto>(okResult.Value);
        Assert.Equal(status.ToString(), returnedDto.Status);
    }

    #endregion

    [Theory]
    [InlineData(SupportReplyStatus.Added, 200)]
    [InlineData(SupportReplyStatus.NotFound, 404)]
    [InlineData(SupportReplyStatus.Forbidden, 403)]
    [InlineData(SupportReplyStatus.Invalid, 400)]
    [InlineData(SupportReplyStatus.Conflict, 409)]
    public async Task AddReply_MapsCommandOutcomeWithoutAdditionalWrites(SupportReplyStatus status, int expected)
    {
        var reply = new SupportReplyDto { SupportReplyId = 12, Message = "Follow up", IsFromAdmin = true };
        _replies.Setup(r => r.AddAdminReplyAsync(10, 1, "Follow up"))
            .ReturnsAsync(new SupportReplyResult(status, reply, "Review the request"));
        var result = (await _controller.AddReply(10, new() { Message = "Follow up" })).Result;
        if (expected == 403) Assert.IsType<ForbidResult>(result);
        else
        {
            var response = Assert.IsAssignableFrom<Microsoft.AspNetCore.Mvc.Infrastructure.IStatusCodeActionResult>(result);
            Assert.Equal(expected, response.StatusCode);
        }
        if (expected == 200) Assert.Same(reply, Assert.IsType<OkObjectResult>(result).Value);
        if (expected is 400 or 409) Assert.Contains("Review the request", Assert.IsAssignableFrom<ObjectResult>(result).Value!.ToString());
        _replies.VerifyAll();
        _mockSupportRepository.VerifyNoOtherCalls();
    }


    #region GetAllRequests Tests

    [Fact]
    public async Task GetAllRequests_ReturnsAllRequests_WithPagination()
    {
        // Arrange
        var requests = new List<SupportRequest>
        {
            new()
            {
                Id = 1,
                UserId = 1,
                Email = "user1@example.com",
                Subject = "Request 1",
                Description = "Description 1",
                Status = SupportRequestStatus.Open,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                Replies = new List<SupportReply>()
            }
        };

        _mockSupportRepository.Setup(r => r.GetAllRequestsAsync(null, false, 50, 0))
            .ReturnsAsync(requests);
        _mockSupportRepository.Setup(r => r.GetRequestCountAsync(null, false))
            .ReturnsAsync(1);

        // Act
        var result = await _controller.GetAllRequests();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        Assert.NotNull(okResult.Value);
    }

    #endregion

    #region DeleteRequest Tests

    [Fact]
    public async Task DeleteRequest_SoftDeletes_WhenRequestExists()
    {
        // Arrange
        _mockSupportRepository.Setup(r => r.SoftDeleteAsync(1))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.DeleteRequest(1);

        // Assert
        Assert.IsType<NoContentResult>(result);
        _mockSupportRepository.Verify(r => r.SoftDeleteAsync(1), Times.Once);
    }

    [Fact]
    public async Task DeleteRequest_ReturnsNotFound_WhenRequestDoesNotExist()
    {
        // Arrange
        _mockSupportRepository.Setup(r => r.SoftDeleteAsync(999))
            .ReturnsAsync(false);

        // Act
        var result = await _controller.DeleteRequest(999);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    #endregion

    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    [InlineData("0")]
    [InlineData("-1")]
    public async Task AddReply_RequiresPositiveAccountIdentity(string? identity)
    {
        _controller.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(identity is null ? [] :
            new[] { new Claim(ClaimTypes.NameIdentifier, identity) }, "TestAuth"));
        Assert.IsType<UnauthorizedResult>((await _controller.AddReply(10, new() { Message = "Reply" })).Result);
        _replies.VerifyNoOtherCalls();
        _mockSupportRepository.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData("closed", SupportRequestStatus.Closed)]
    [InlineData("not-a-status", null)]
    [InlineData("", null)]
    public async Task List_UsesSameFiltersForItemsAndCount(string status, SupportRequestStatus? expected)
    {
        _mockSupportRepository.Setup(r => r.GetAllRequestsAsync(expected, true, 7, 14))
            .ReturnsAsync(new[] { new SupportRequest { Id = 10, Subject = "Ticket", Status = SupportRequestStatus.Closed } });
        _mockSupportRepository.Setup(r => r.GetRequestCountAsync(expected, true)).ReturnsAsync(20);
        var response = Assert.IsType<OkObjectResult>((await _controller.GetAllRequests(status, true, 7, 14)).Result);
        var json = System.Text.Json.JsonSerializer.SerializeToElement(response.Value);
        Assert.Equal(20, json.GetProperty("total").GetInt32());
        Assert.Equal(7, json.GetProperty("limit").GetInt32());
        Assert.Equal(14, json.GetProperty("offset").GetInt32());
        Assert.Equal(10, json.GetProperty("items")[0].GetProperty("SupportRequestId").GetInt32());
        _mockSupportRepository.VerifyAll();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task GetRequest_MapsExistenceAndIncludesReplyDetails(bool exists)
    {
        _mockSupportRepository.Setup(r => r.GetRequestByIdAsync(10, true)).ReturnsAsync(exists
            ? new SupportRequest { Id = 10, Replies = new[] { new SupportReply { Id = 12, Message = "Reply", IsFromAdmin = true } } }
            : null);
        var response = (await _controller.GetRequest(10)).Result;
        if (!exists) Assert.IsType<NotFoundResult>(response);
        else
        {
            var value = Assert.IsType<SupportRequestDto>(Assert.IsType<OkObjectResult>(response).Value);
            Assert.Equal(10, value.SupportRequestId);
            Assert.Equal("Reply", Assert.Single(value.Replies).Message);
        }
        _mockSupportRepository.VerifyAll();
        _mockSupportRepository.VerifyNoOtherCalls();
    }
}
