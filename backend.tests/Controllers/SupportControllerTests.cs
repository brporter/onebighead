using backend.Controllers;
using backend.Data;
using backend.DTOs;
using backend.Models;
using backend.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Security.Claims;

namespace backend.Tests.Controllers;

[Trait("Category", "Unit")]
public class SupportControllerTests
{
    private readonly Mock<ISupportRepository> _mockSupportRepository;
    private readonly Mock<IUserRepository> _mockUserRepository;
    private readonly Mock<IEmailService> _mockEmailService;
    private readonly SupportController _controller;

    public SupportControllerTests()
    {
        _mockSupportRepository = new Mock<ISupportRepository>();
        _mockUserRepository = new Mock<IUserRepository>();
        _mockEmailService = new Mock<IEmailService>();
        _controller = new SupportController(
            _mockSupportRepository.Object,
            _mockUserRepository.Object,
            _mockEmailService.Object
        );

        SetupAuthenticatedUser(1, "test@example.com");
    }

    private void SetupAuthenticatedUser(int userId, string email)
    {
        var claims = new List<Claim>
        {
            new("tenant_id", "1"),
            new("sub", userId.ToString()),
            new(ClaimTypes.NameIdentifier, userId.ToString()),
            new(ClaimTypes.Email, email)
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var claimsPrincipal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = claimsPrincipal }
        };
    }

    private void SetupAnonymousUser()
    {
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal() }
        };
    }

    #region CreateRequest Tests

    [Fact]
    public async Task CreateRequest_AuthenticatedUser_CreatesRequestWithUserId()
    {
        // Arrange
        var user = new User { Id = 1, Email = "test@example.com" };
        _mockUserRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(user);

        var createdRequest = new SupportRequest
        {
            Id = 1,
            UserId = 1,
            Email = "test@example.com",
            Subject = "Test Subject",
            Description = "Test Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow
        };
        _mockSupportRepository.Setup(r => r.CreateRequestAsync(It.IsAny<SupportRequest>()))
            .ReturnsAsync(createdRequest);

        var dto = new CreateSupportRequestDto
        {
            Subject = "Test Subject",
            Description = "Test Description"
        };

        // Act
        var result = await _controller.CreateRequest(dto);

        // Assert
        var createdResult = Assert.IsType<CreatedAtActionResult>(result.Result);
        var returnedDto = Assert.IsType<SupportRequestDto>(createdResult.Value);
        Assert.Equal(1, returnedDto.SupportRequestId);
        Assert.Equal("test@example.com", returnedDto.Email);
    }

    [Fact]
    public async Task CreateRequest_AnonymousUser_RequiresEmail()
    {
        // Arrange
        SetupAnonymousUser();
        var dto = new CreateSupportRequestDto
        {
            Subject = "Test Subject",
            Description = "Test Description"
            // No email provided
        };

        // Act
        var result = await _controller.CreateRequest(dto);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
        Assert.Contains("email", badRequestResult.Value?.ToString()?.ToLower());
    }

    [Fact]
    public async Task CreateRequest_AnonymousUser_CreatesRequestWithEmail()
    {
        // Arrange
        SetupAnonymousUser();
        var createdRequest = new SupportRequest
        {
            Id = 1,
            UserId = null,
            Email = "anonymous@example.com",
            Subject = "Test Subject",
            Description = "Test Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow
        };
        _mockSupportRepository.Setup(r => r.CreateRequestAsync(It.IsAny<SupportRequest>()))
            .ReturnsAsync(createdRequest);

        var dto = new CreateSupportRequestDto
        {
            Subject = "Test Subject",
            Description = "Test Description",
            Email = "anonymous@example.com"
        };

        // Act
        var result = await _controller.CreateRequest(dto);

        // Assert
        var createdResult = Assert.IsType<CreatedAtActionResult>(result.Result);
        var returnedDto = Assert.IsType<SupportRequestDto>(createdResult.Value);
        Assert.Null(returnedDto.UserId);
        Assert.Equal("anonymous@example.com", returnedDto.Email);
    }

    #endregion

    #region GetMyRequests Tests

    [Fact]
    public async Task GetMyRequests_ReturnsUserRequests()
    {
        // Arrange
        var requests = new List<SupportRequest>
        {
            new()
            {
                Id = 1,
                UserId = 1,
                Email = "test@example.com",
                Subject = "Request 1",
                Description = "Description 1",
                Status = SupportRequestStatus.Open,
                CreatedAt = DateTime.UtcNow,
                Replies = new List<SupportReply>()
            },
            new()
            {
                Id = 2,
                UserId = 1,
                Email = "test@example.com",
                Subject = "Request 2",
                Description = "Description 2",
                Status = SupportRequestStatus.Resolved,
                CreatedAt = DateTime.UtcNow,
                Replies = new List<SupportReply>()
            }
        };

        _mockSupportRepository.Setup(r => r.GetRequestsForUserAsync(1))
            .ReturnsAsync(requests);

        // Act
        var result = await _controller.GetMyRequests();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedRequests = Assert.IsAssignableFrom<IEnumerable<SupportRequestDto>>(okResult.Value);
        Assert.Equal(2, returnedRequests.Count());
    }

    #endregion

    #region GetRequest Tests

    [Fact]
    public async Task GetRequest_ReturnsRequest_WhenUserOwnsIt()
    {
        // Arrange
        var request = new SupportRequest
        {
            Id = 1,
            UserId = 1,
            Email = "test@example.com",
            Subject = "Test Subject",
            Description = "Test Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            Replies = new List<SupportReply>
            {
                new()
                {
                    Id = 1,
                    SupportRequestId = 1,
                    IsFromAdmin = true,
                    Message = "Admin reply",
                    CreatedAt = DateTime.UtcNow
                }
            }
        };

        _mockSupportRepository.Setup(r => r.GetRequestByIdAsync(1, It.IsAny<bool>()))
            .ReturnsAsync(request);

        // Act
        var result = await _controller.GetRequest(1);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedDto = Assert.IsType<SupportRequestDto>(okResult.Value);
        Assert.Equal(1, returnedDto.SupportRequestId);
        Assert.Single(returnedDto.Replies);
    }

    [Fact]
    public async Task GetRequest_ReturnsNotFound_WhenRequestDoesNotExist()
    {
        // Arrange
        _mockSupportRepository.Setup(r => r.GetRequestByIdAsync(999, It.IsAny<bool>()))
            .ReturnsAsync((SupportRequest?)null);

        // Act
        var result = await _controller.GetRequest(999);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    [Fact]
    public async Task GetRequest_ReturnsForbidden_WhenUserDoesNotOwnRequest()
    {
        // Arrange
        var request = new SupportRequest
        {
            Id = 1,
            UserId = 2, // Different user
            Email = "other@example.com",
            Subject = "Test Subject",
            Description = "Test Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            Replies = new List<SupportReply>()
        };

        _mockSupportRepository.Setup(r => r.GetRequestByIdAsync(1, It.IsAny<bool>()))
            .ReturnsAsync(request);

        // Act
        var result = await _controller.GetRequest(1);

        // Assert
        Assert.IsType<ForbidResult>(result.Result);
    }

    #endregion

    #region AddReply Tests

    [Fact]
    public async Task AddReply_CreatesReply_WhenUserOwnsRequest()
    {
        // Arrange
        var request = new SupportRequest
        {
            Id = 1,
            UserId = 1,
            Email = "test@example.com",
            Subject = "Test Subject",
            Description = "Test Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            Replies = new List<SupportReply>()
        };

        var createdReply = new SupportReply
        {
            Id = 1,
            SupportRequestId = 1,
            UserId = 1,
            IsFromAdmin = false,
            Message = "User reply",
            CreatedAt = DateTime.UtcNow
        };

        _mockSupportRepository.Setup(r => r.GetRequestByIdAsync(1, It.IsAny<bool>()))
            .ReturnsAsync(request);
        _mockSupportRepository.Setup(r => r.AddReplyAsync(It.IsAny<SupportReply>()))
            .ReturnsAsync(createdReply);

        var dto = new CreateSupportReplyDto { Message = "User reply" };

        // Act
        var result = await _controller.AddReply(1, dto);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedDto = Assert.IsType<SupportReplyDto>(okResult.Value);
        Assert.Equal("User reply", returnedDto.Message);
        Assert.False(returnedDto.IsFromAdmin);
    }

    #endregion

    #region GetUnreadCount Tests

    [Fact]
    public async Task GetUnreadCount_ReturnsCount()
    {
        // Arrange
        _mockSupportRepository.Setup(r => r.GetUnreadCountForUserAsync(1))
            .ReturnsAsync(5);

        // Act
        var result = await _controller.GetUnreadCount();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var countDto = Assert.IsType<SupportUnreadCountDto>(okResult.Value);
        Assert.Equal(5, countDto.UnreadCount);
    }

    #endregion

    #region DeleteRequest Tests

    [Fact]
    public async Task DeleteRequest_SoftDeletes_WhenUserOwnsRequest()
    {
        // Arrange
        var request = new SupportRequest
        {
            Id = 1,
            UserId = 1,
            Email = "test@example.com",
            Subject = "Test Subject",
            Description = "Test Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            Replies = new List<SupportReply>()
        };

        _mockSupportRepository.Setup(r => r.GetRequestByIdAsync(1, false))
            .ReturnsAsync(request);
        _mockSupportRepository.Setup(r => r.SoftDeleteAsync(1))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.DeleteRequest(1);

        // Assert
        Assert.IsType<NoContentResult>(result);
        _mockSupportRepository.Verify(r => r.SoftDeleteAsync(1), Times.Once);
    }

    #endregion
}
