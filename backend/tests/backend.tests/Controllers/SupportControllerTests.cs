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
public class SupportControllerTests
{
    private readonly Mock<ISupportRepository> _mockSupportRepository;
    private readonly Mock<IUserRepository> _mockUserRepository;
    private readonly Mock<IEmailService> _mockEmailService;
    private readonly Mock<ISupportReplies> _replies = new(MockBehavior.Strict);
    private readonly SupportController _controller;

    public SupportControllerTests()
    {
        _mockSupportRepository = new Mock<ISupportRepository>();
        _mockUserRepository = new Mock<IUserRepository>();
        _mockEmailService = new Mock<IEmailService>();
        _controller = new SupportController(
            new SupportRequestCreator(_mockSupportRepository.Object, _mockUserRepository.Object, _mockEmailService.Object),
            new SupportRequests(_mockSupportRepository.Object), _replies.Object);

        SetupAuthenticatedUser(1, "test@example.com");
    }

    private void SetupAuthenticatedUser(int userId, string email)
    {
        var claims = new List<Claim>
        {
            new("workspace_id", "1"),
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
        Assert.IsType<NotFoundResult>(result.Result);
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
        var reply = new SupportReplyDto { SupportReplyId = 12, Message = "Follow up", IsFromAdmin = false };
        _replies.Setup(r => r.AddUserReplyAsync(10, 1, "Follow up"))
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

    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    [InlineData("0")]
    [InlineData("-1")]
    public async Task ProtectedOperations_RejectMissingOrInvalidIdentityBeforeReadingData(string? identity)
    {
        _controller.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(identity is null ? [] :
            new[] { new Claim(ClaimTypes.NameIdentifier, identity) }, "TestAuth"));
        Assert.IsType<UnauthorizedResult>((await _controller.GetMyRequests()).Result);
        Assert.IsType<UnauthorizedResult>((await _controller.GetRequest(1)).Result);
        Assert.IsType<UnauthorizedResult>((await _controller.AddReply(1, new() { Message = "Reply" })).Result);
        Assert.IsType<UnauthorizedResult>(await _controller.DeleteRequest(1));
        Assert.IsType<UnauthorizedResult>((await _controller.GetUnreadCount()).Result);
        Assert.IsType<UnauthorizedResult>(await _controller.MarkAsRead(1));
        _mockSupportRepository.VerifyNoOtherCalls();
        _replies.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task CreateRequest_MissingAccountDoesNotWriteOrSendConfirmation()
    {
        Assert.IsType<UnauthorizedResult>((await _controller.CreateRequest(new()
            { Email = "spoofed@example.test", Subject = "Help", Description = "Description" })).Result);
        _mockSupportRepository.VerifyNoOtherCalls();
        _mockEmailService.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(null)]
    [InlineData(2)]
    public async Task RequestOwnedByAnotherOrAnonymousUser_IsNotExposedOrMutated(int? owner)
    {
        _mockSupportRepository.Setup(r => r.GetRequestByIdAsync(10, It.IsAny<bool>()))
            .ReturnsAsync(new SupportRequest { Id = 10, UserId = owner });
        Assert.IsType<NotFoundResult>((await _controller.GetRequest(10)).Result);
        Assert.IsType<NotFoundResult>(await _controller.DeleteRequest(10));
        Assert.IsType<NotFoundResult>(await _controller.MarkAsRead(10));
        _mockSupportRepository.Verify(r => r.GetRequestByIdAsync(10, true), Times.Once);
        _mockSupportRepository.Verify(r => r.GetRequestByIdAsync(10, false), Times.Exactly(2));
        _mockSupportRepository.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task MissingRequest_CannotBeDeletedOrMarkedRead()
    {
        Assert.IsType<NotFoundResult>(await _controller.DeleteRequest(10));
        Assert.IsType<NotFoundResult>(await _controller.MarkAsRead(10));
        _mockSupportRepository.Verify(r => r.GetRequestByIdAsync(10, false), Times.Exactly(2));
        _mockSupportRepository.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task MarkRead_UsesCurrentOwnerAndDoesNotHappenDuringRead()
    {
        _mockSupportRepository.Setup(r => r.GetRequestByIdAsync(10, It.IsAny<bool>()))
            .ReturnsAsync(new SupportRequest { Id = 10, UserId = 1 });
        Assert.IsType<OkObjectResult>((await _controller.GetRequest(10)).Result);
        _mockSupportRepository.Verify(r => r.MarkRepliesAsReadAsync(It.IsAny<int>(), It.IsAny<int>()), Times.Never);
        Assert.IsType<NoContentResult>(await _controller.MarkAsRead(10));
        _mockSupportRepository.Verify(r => r.MarkRepliesAsReadAsync(10, 1), Times.Once);
    }
}
