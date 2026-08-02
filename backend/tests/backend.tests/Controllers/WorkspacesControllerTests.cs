using OneBigHead.Server.Authentication;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using System.Security.Claims;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class WorkspacesControllerTests
{
    private readonly Mock<IWorkspaceRepository> _mockWorkspaceRepository;
    private readonly Mock<IWorkspaceUserRepository> _mockWorkspaceUserRepository;
    private readonly Mock<IUserRepository> _mockUserRepository;
    private readonly Mock<ICollectionRepository> _mockCollectionRepository;
    private readonly Mock<ICategoryRepository> _mockCategoryRepository;
    private readonly Mock<IItemTemplateRepository> _mockItemTemplateRepository;
    private readonly Mock<IThemeRepository> _mockThemeRepository;
    private readonly Mock<ITokenService> _mockTokenService;
    private readonly Mock<ITokenRevocationService> _mockTokenRevocationService;
    private readonly Mock<IWorkspaceService> _mockWorkspaceService;
    private readonly Mock<ILogger<WorkspacesController>> _mockLogger;
    private readonly WorkspacesController _controller;
    private const int TestWorkspaceId = 1;
    private const int TestUserId = 1;

    public WorkspacesControllerTests()
    {
        _mockWorkspaceRepository = new Mock<IWorkspaceRepository>();
        _mockWorkspaceUserRepository = new Mock<IWorkspaceUserRepository>();
        _mockUserRepository = new Mock<IUserRepository>();
        _mockCollectionRepository = new Mock<ICollectionRepository>();
        _mockCategoryRepository = new Mock<ICategoryRepository>();
        _mockItemTemplateRepository = new Mock<IItemTemplateRepository>();
        _mockThemeRepository = new Mock<IThemeRepository>();
        _mockTokenService = new Mock<ITokenService>();
        _mockTokenRevocationService = new Mock<ITokenRevocationService>();
        _mockWorkspaceService = new Mock<IWorkspaceService>();
        _mockLogger = new Mock<ILogger<WorkspacesController>>();

        var settings = Options.Create(new AuthenticationSettings());

        _controller = new WorkspacesController(
            _mockWorkspaceRepository.Object,
            _mockWorkspaceUserRepository.Object,
            _mockUserRepository.Object,
            _mockCollectionRepository.Object,
            _mockCategoryRepository.Object,
            _mockItemTemplateRepository.Object,
            _mockThemeRepository.Object,
            _mockTokenService.Object,
            _mockTokenRevocationService.Object,
            _mockWorkspaceService.Object,
            settings,
            _mockLogger.Object);

        var claims = new List<Claim>
        {
            new("workspace_id", TestWorkspaceId.ToString()),
            new("sub", TestUserId.ToString()),
            new(ClaimTypes.NameIdentifier, TestUserId.ToString()),
            new(ClaimTypes.Email, "test@example.com")
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var claimsPrincipal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = claimsPrincipal }
        };
    }

    #region UpdateWorkspace Tests

    [Fact]
    public async Task UpdateWorkspace_ValidNameAndSlug_ReturnsOkWithSlugAndPublicUrl()
    {
        // Arrange
        var workspace = new Workspace { Id = TestWorkspaceId, Name = "Old Name" };
        _mockWorkspaceUserRepository.Setup(r => r.GetMembershipAsync(TestUserId, TestWorkspaceId))
            .ReturnsAsync(new WorkspaceUser { WorkspaceId = TestWorkspaceId, UserId = TestUserId, WorkspaceRole = WorkspaceRole.WorkspaceAdmin, Workspace = workspace });
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId))
            .ReturnsAsync(workspace);
        _mockWorkspaceRepository.Setup(r => r.IsSlugTakenAsync("my-workspace", TestWorkspaceId))
            .ReturnsAsync(false);

        var request = new UpdateWorkspaceRequest { Name = "New Name", Slug = "my-workspace" };

        // Act
        var result = await _controller.UpdateWorkspace(TestWorkspaceId, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<UpdateWorkspaceResponse>(okResult.Value);
        Assert.Equal(TestWorkspaceId, response.WorkspaceId);
        Assert.Equal("New Name", response.WorkspaceName);
        Assert.Equal("my-workspace", response.Slug);
        Assert.Equal("/public/my-workspace", response.PublicUrl);
        _mockWorkspaceRepository.Verify(r => r.UpdateAsync(It.Is<Workspace>(w => w.Name == "New Name" && w.Slug == "my-workspace")), Times.Once);
    }

    [Fact]
    public async Task UpdateWorkspace_NullSlug_ReturnsOkWithNullPublicUrl()
    {
        // Arrange
        var workspace = new Workspace { Id = TestWorkspaceId, Name = "Old Name", Slug = "old-slug" };
        _mockWorkspaceUserRepository.Setup(r => r.GetMembershipAsync(TestUserId, TestWorkspaceId))
            .ReturnsAsync(new WorkspaceUser { WorkspaceId = TestWorkspaceId, UserId = TestUserId, WorkspaceRole = WorkspaceRole.WorkspaceAdmin, Workspace = workspace });
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId))
            .ReturnsAsync(workspace);

        var request = new UpdateWorkspaceRequest { Name = "New Name", Slug = null };

        // Act
        var result = await _controller.UpdateWorkspace(TestWorkspaceId, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<UpdateWorkspaceResponse>(okResult.Value);
        Assert.Null(response.Slug);
        Assert.Null(response.PublicUrl);
        _mockWorkspaceRepository.Verify(r => r.UpdateAsync(It.Is<Workspace>(w => w.Slug == null)), Times.Once);
    }

    [Fact]
    public async Task UpdateWorkspace_SlugAlreadyTaken_ReturnsConflict()
    {
        // Arrange
        var workspace = new Workspace { Id = TestWorkspaceId, Name = "Old Name" };
        _mockWorkspaceUserRepository.Setup(r => r.GetMembershipAsync(TestUserId, TestWorkspaceId))
            .ReturnsAsync(new WorkspaceUser { WorkspaceId = TestWorkspaceId, UserId = TestUserId, WorkspaceRole = WorkspaceRole.WorkspaceAdmin, Workspace = workspace });
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId))
            .ReturnsAsync(workspace);
        _mockWorkspaceRepository.Setup(r => r.IsSlugTakenAsync("taken-slug", TestWorkspaceId))
            .ReturnsAsync(true);

        var request = new UpdateWorkspaceRequest { Name = "New Name", Slug = "taken-slug" };

        // Act
        var result = await _controller.UpdateWorkspace(TestWorkspaceId, request);

        // Assert
        var conflictResult = Assert.IsType<ConflictObjectResult>(result);
        _mockWorkspaceRepository.Verify(r => r.UpdateAsync(It.IsAny<Workspace>()), Times.Never);
    }

    [Fact]
    public async Task UpdateWorkspace_EmptyName_ReturnsBadRequest()
    {
        // Arrange
        var request = new UpdateWorkspaceRequest { Name = "", Slug = "my-slug" };

        // Act
        var result = await _controller.UpdateWorkspace(TestWorkspaceId, request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task UpdateWorkspace_NotMember_ReturnsNotFound()
    {
        // Arrange
        _mockWorkspaceUserRepository.Setup(r => r.GetMembershipAsync(TestUserId, TestWorkspaceId))
            .ReturnsAsync((WorkspaceUser?)null);

        var request = new UpdateWorkspaceRequest { Name = "New Name" };

        // Act
        var result = await _controller.UpdateWorkspace(TestWorkspaceId, request);

        // Assert
        var notFoundResult = Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task UpdateWorkspace_NotAdmin_ReturnsForbid()
    {
        // Arrange
        var workspace = new Workspace { Id = TestWorkspaceId, Name = "Old Name" };
        _mockWorkspaceUserRepository.Setup(r => r.GetMembershipAsync(TestUserId, TestWorkspaceId))
            .ReturnsAsync(new WorkspaceUser { WorkspaceId = TestWorkspaceId, UserId = TestUserId, WorkspaceRole = WorkspaceRole.Normal, Workspace = workspace });

        var request = new UpdateWorkspaceRequest { Name = "New Name" };

        // Act
        var result = await _controller.UpdateWorkspace(TestWorkspaceId, request);

        // Assert
        Assert.IsType<ForbidResult>(result);
    }

    [Fact]
    public async Task UpdateWorkspace_WorkspaceNotFound_ReturnsNotFound()
    {
        // Arrange
        _mockWorkspaceUserRepository.Setup(r => r.GetMembershipAsync(TestUserId, TestWorkspaceId))
            .ReturnsAsync(new WorkspaceUser { WorkspaceId = TestWorkspaceId, UserId = TestUserId, WorkspaceRole = WorkspaceRole.WorkspaceAdmin, Workspace = new Workspace() });
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId))
            .ReturnsAsync((Workspace?)null);

        var request = new UpdateWorkspaceRequest { Name = "New Name" };

        // Act
        var result = await _controller.UpdateWorkspace(TestWorkspaceId, request);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task UpdateWorkspace_EmptySlug_DoesNotCheckSlugUniqueness()
    {
        // Arrange
        var workspace = new Workspace { Id = TestWorkspaceId, Name = "Old Name" };
        _mockWorkspaceUserRepository.Setup(r => r.GetMembershipAsync(TestUserId, TestWorkspaceId))
            .ReturnsAsync(new WorkspaceUser { WorkspaceId = TestWorkspaceId, UserId = TestUserId, WorkspaceRole = WorkspaceRole.WorkspaceAdmin, Workspace = workspace });
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId))
            .ReturnsAsync(workspace);

        var request = new UpdateWorkspaceRequest { Name = "New Name", Slug = "" };

        // Act
        var result = await _controller.UpdateWorkspace(TestWorkspaceId, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        _mockWorkspaceRepository.Verify(r => r.IsSlugTakenAsync(It.IsAny<string>(), It.IsAny<int?>()), Times.Never);
    }

    #endregion

    #region TransferAdmin Tests

    private const int NewAdminUserId = 99;

    private void SetupTransferAdminMemberships()
    {
        _mockWorkspaceUserRepository.Setup(r => r.GetMembershipAsync(TestUserId, TestWorkspaceId))
            .ReturnsAsync(new WorkspaceUser
            {
                UserId = TestUserId,
                WorkspaceId = TestWorkspaceId,
                WorkspaceRole = WorkspaceRole.WorkspaceAdmin
            });
        _mockWorkspaceUserRepository.Setup(r => r.GetMembershipAsync(NewAdminUserId, TestWorkspaceId))
            .ReturnsAsync(new WorkspaceUser
            {
                UserId = NewAdminUserId,
                WorkspaceId = TestWorkspaceId,
                WorkspaceRole = WorkspaceRole.Normal
            });
    }

    [Fact]
    public async Task TransferAdmin_Success_UpdatesRolesAndRevokesBothUsersTokens()
    {
        // Arrange
        SetupTransferAdminMemberships();
        _mockUserRepository.Setup(r => r.GetByIdAsync(TestUserId))
            .ReturnsAsync(new User { Id = TestUserId, ActiveWorkspaceId = TestWorkspaceId, Email = "test@example.com" });
        _mockTokenService.Setup(t => t.GenerateAppToken(It.IsAny<User>(), WorkspaceRole.Normal))
            .Returns("new-token");

        // Act
        var result = await _controller.TransferAdmin(TestWorkspaceId, new TransferAdminRequest { NewAdminUserId = NewAdminUserId });

        // Assert
        Assert.IsType<OkObjectResult>(result);
        _mockWorkspaceUserRepository.Verify(r => r.UpdateRoleAsync(NewAdminUserId, TestWorkspaceId, WorkspaceRole.WorkspaceAdmin), Times.Once);
        _mockWorkspaceUserRepository.Verify(r => r.UpdateRoleAsync(TestUserId, TestWorkspaceId, WorkspaceRole.Normal), Times.Once);
        _mockTokenRevocationService.Verify(s => s.RevokeAsync(NewAdminUserId), Times.Once);
        _mockTokenRevocationService.Verify(s => s.RevokeAsync(TestUserId), Times.Once);
    }

    [Fact]
    public async Task TransferAdmin_NotAMember_ReturnsNotFoundWithoutRevoking()
    {
        // Arrange
        _mockWorkspaceUserRepository.Setup(r => r.GetMembershipAsync(TestUserId, TestWorkspaceId))
            .ReturnsAsync((WorkspaceUser?)null);

        // Act
        var result = await _controller.TransferAdmin(TestWorkspaceId, new TransferAdminRequest { NewAdminUserId = NewAdminUserId });

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
        _mockTokenRevocationService.Verify(s => s.RevokeAsync(It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task TransferAdmin_NotAdmin_ReturnsForbidWithoutRevoking()
    {
        // Arrange
        _mockWorkspaceUserRepository.Setup(r => r.GetMembershipAsync(TestUserId, TestWorkspaceId))
            .ReturnsAsync(new WorkspaceUser
            {
                UserId = TestUserId,
                WorkspaceId = TestWorkspaceId,
                WorkspaceRole = WorkspaceRole.Normal
            });

        // Act
        var result = await _controller.TransferAdmin(TestWorkspaceId, new TransferAdminRequest { NewAdminUserId = NewAdminUserId });

        // Assert
        Assert.IsType<ForbidResult>(result);
        _mockTokenRevocationService.Verify(s => s.RevokeAsync(It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task TransferAdmin_TargetNotAMember_ReturnsBadRequestWithoutRevoking()
    {
        // Arrange
        _mockWorkspaceUserRepository.Setup(r => r.GetMembershipAsync(TestUserId, TestWorkspaceId))
            .ReturnsAsync(new WorkspaceUser
            {
                UserId = TestUserId,
                WorkspaceId = TestWorkspaceId,
                WorkspaceRole = WorkspaceRole.WorkspaceAdmin
            });
        _mockWorkspaceUserRepository.Setup(r => r.GetMembershipAsync(NewAdminUserId, TestWorkspaceId))
            .ReturnsAsync((WorkspaceUser?)null);

        // Act
        var result = await _controller.TransferAdmin(TestWorkspaceId, new TransferAdminRequest { NewAdminUserId = NewAdminUserId });

        // Assert
        Assert.IsType<BadRequestObjectResult>(result);
        _mockTokenRevocationService.Verify(s => s.RevokeAsync(It.IsAny<int>()), Times.Never);
    }

    #endregion
}
