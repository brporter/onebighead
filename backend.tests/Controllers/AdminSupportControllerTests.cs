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
    private readonly Mock<IEmailService> _mockEmailService;
    private readonly AdminSupportController _controller;

    public AdminSupportControllerTests()
    {
        _mockSupportRepository = new Mock<ISupportRepository>();
        _mockEmailService = new Mock<IEmailService>();
        _controller = new AdminSupportController(
            _mockSupportRepository.Object,
            _mockEmailService.Object
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

    #region AddReply Tests

    [Fact]
    public async Task AddReply_CreatesAdminReply_AndSendsEmail()
    {
        // Arrange
        var request = new SupportRequest
        {
            Id = 1,
            UserId = 2,
            Email = "user@example.com",
            Subject = "Test Subject",
            Description = "Test Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            Replies = new List<SupportReply>()
        };

        var createdReply = new SupportReply
        {
            Id = 1,
            SupportRequestId = 1,
            UserId = 1, // Admin user
            IsFromAdmin = true,
            Message = "Admin response",
            CreatedAt = DateTime.UtcNow,
            IsRead = false
        };

        _mockSupportRepository.Setup(r => r.GetRequestByIdAsync(1, false))
            .ReturnsAsync(request);
        _mockSupportRepository.Setup(r => r.AddReplyAsync(It.IsAny<SupportReply>()))
            .ReturnsAsync(createdReply);
        _mockSupportRepository.Setup(r => r.UpdateStatusAsync(1, SupportRequestStatus.InProgress))
            .ReturnsAsync(request);
        _mockEmailService.Setup(e => e.SendSupportReplyNotificationAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<bool>()))
            .Returns(Task.CompletedTask);

        var dto = new CreateSupportReplyDto { Message = "Admin response" };

        // Act
        var result = await _controller.AddReply(1, dto);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedDto = Assert.IsType<SupportReplyDto>(okResult.Value);
        Assert.True(returnedDto.IsFromAdmin);
        Assert.Equal("Admin response", returnedDto.Message);

        // Verify email was sent
        _mockEmailService.Verify(e => e.SendSupportReplyNotificationAsync(
            "user@example.com", "Test Subject", "Admin response", 1, true), Times.Once);
    }

    [Fact]
    public async Task AddReply_ReturnsBadRequest_WhenRequestIsDeleted()
    {
        // Arrange
        var deletedRequest = new SupportRequest
        {
            Id = 1,
            UserId = 2,
            Email = "user@example.com",
            Subject = "Test Subject",
            Description = "Test Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            IsDeleted = true,
            DeletedAt = DateTime.UtcNow,
            Replies = new List<SupportReply>()
        };

        _mockSupportRepository.Setup(r => r.GetRequestByIdAsync(1, false))
            .ReturnsAsync(deletedRequest);

        var dto = new CreateSupportReplyDto { Message = "Admin response" };

        // Act
        var result = await _controller.AddReply(1, dto);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
        Assert.Contains("deleted", badRequestResult.Value?.ToString()?.ToLower());
    }

    #endregion

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
}
