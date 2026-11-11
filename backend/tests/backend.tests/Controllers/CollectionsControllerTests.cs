using OneBigHead.Server.Services.Collections;
using OneBigHead.Server.Services;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using System.Security.Claims;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class CollectionsControllerTests
{
    private readonly Mock<ICollectionRepository> _mockCollectionRepository;
    private readonly Mock<IItemTemplateRepository> _mockItemTemplateRepository = new();
    private readonly Mock<ICollectionSetupService> _mockSetupService = new();
    private readonly Mock<IThemeRepository> _mockThemeRepository;
    private readonly Mock<ICollectionStatisticsRepository> _mockCollectionStatisticsRepository;
    private readonly Mock<ICollectionDetails> _details = new();
    private readonly Mock<ICollectionDeletion> _deletion = new();
    private readonly CollectionsController _controller;
    private const int TestWorkspaceId = 1;
    private const int TestUserId = 1;

    public CollectionsControllerTests()
    {
        _mockCollectionRepository = new Mock<ICollectionRepository>();
        _mockThemeRepository = new Mock<IThemeRepository>();
        _mockCollectionStatisticsRepository = new Mock<ICollectionStatisticsRepository>();
        _controller = new CollectionsController(
            _mockCollectionRepository.Object,
            _mockItemTemplateRepository.Object,
            _mockSetupService.Object,
            _mockThemeRepository.Object,
            _mockCollectionStatisticsRepository.Object, _details.Object, _deletion.Object);

        var claims = new List<Claim>
        {
            new("workspace_id", TestWorkspaceId.ToString()),
            new("sub", TestUserId.ToString()),
            new(ClaimTypes.NameIdentifier, "1"),
            new(ClaimTypes.Email, "test@example.com")
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var claimsPrincipal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = claimsPrincipal }
        };
    }

    #region GetCollections Tests

    [Fact]
    public async Task GetCollections_ReturnsOkResult_WithListOfCollections()
    {
        // Arrange
        var collections = new List<Collection>
        {
            new() { Id = 1, WorkspaceId = TestWorkspaceId, Name = "Collection 1", Slug = "collection-1" },
            new() { Id = 2, WorkspaceId = TestWorkspaceId, Name = "Collection 2", Slug = "collection-2" }
        };
        _mockCollectionRepository.Setup(repo => repo.GetAllAsync(TestWorkspaceId))
            .ReturnsAsync(collections);

        // Act
        var result = await _controller.GetCollections();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCollections = Assert.IsAssignableFrom<IEnumerable<Collection>>(okResult.Value);
        Assert.Equal(2, returnedCollections.Count());
    }

    [Fact]
    public async Task GetCollections_ReturnsOkResult_WithEmptyList_WhenNoCollections()
    {
        // Arrange
        _mockCollectionRepository.Setup(repo => repo.GetAllAsync(TestWorkspaceId))
            .ReturnsAsync(new List<Collection>());

        // Act
        var result = await _controller.GetCollections();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCollections = Assert.IsAssignableFrom<IEnumerable<Collection>>(okResult.Value);
        Assert.Empty(returnedCollections);
    }

    #endregion

    #region GetCollection Tests

    [Fact]
    public async Task GetCollection_ReturnsOkResult_WhenCollectionExists()
    {
        // Arrange
        var collection = new Collection { Id = 1, WorkspaceId = TestWorkspaceId, Name = "Test Collection", Slug = "test-collection" };
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(collection);

        // Act
        var result = await _controller.GetCollection(1);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCollection = Assert.IsType<Collection>(okResult.Value);
        Assert.Equal("Test Collection", returnedCollection.Name);
    }

    [Fact]
    public async Task GetCollection_ReturnsNotFound_WhenCollectionDoesNotExist()
    {
        // Arrange
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(999, TestWorkspaceId))
            .ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.GetCollection(999);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    #endregion

    #region GetCollectionBySlug Tests

    [Fact]
    public async Task GetCollectionBySlug_ReturnsOkResult_WhenCollectionExists()
    {
        // Arrange
        var collection = new Collection { Id = 1, WorkspaceId = TestWorkspaceId, Name = "Test Collection", Slug = "test-collection" };
        _mockCollectionRepository.Setup(repo => repo.GetBySlugAsync("test-collection", TestWorkspaceId))
            .ReturnsAsync(collection);

        // Act
        var result = await _controller.GetCollectionBySlug("test-collection");

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCollection = Assert.IsType<Collection>(okResult.Value);
        Assert.Equal("test-collection", returnedCollection.Slug);
    }

    [Fact]
    public async Task GetCollectionBySlug_ReturnsNotFound_WhenCollectionDoesNotExist()
    {
        // Arrange
        _mockCollectionRepository.Setup(repo => repo.GetBySlugAsync("nonexistent", TestWorkspaceId))
            .ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.GetCollectionBySlug("nonexistent");

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    #endregion

    [Fact]
    public async Task CreateCollection_DelegatesSetupAndReturnsCreatedResource()
    {
        var created = new Collection { Id = 42, WorkspaceId = TestWorkspaceId, Name = "New" };
        _mockSetupService.Setup(s => s.CreateAsync(It.IsAny<Collection>(), null)).ReturnsAsync(created);
        var result = await _controller.CreateCollection(new CreateCollectionRequest { Name = "New", Description = "Details", HeroImageUrl = "/hero.jpg" });
        var response = Assert.IsType<CreatedAtActionResult>(result.Result);
        Assert.Same(created, response.Value);
        Assert.Equal(42, response.RouteValues!["id"]);
        _mockSetupService.Verify(s => s.CreateAsync(It.Is<Collection>(c => c.WorkspaceId == TestWorkspaceId && c.Name == "New" && c.Description == "Details" && c.HeroImageUrl == "/hero.jpg"), null), Times.Once);
    }


    [Theory]
    [InlineData(CollectionWriteStatus.NotFound, typeof(NotFoundResult))]
    [InlineData(CollectionWriteStatus.Forbidden, typeof(ForbidResult))]
    [InlineData(CollectionWriteStatus.Invalid, typeof(BadRequestObjectResult))]
    [InlineData(CollectionWriteStatus.Conflict, typeof(ConflictObjectResult))]
    public async Task Mutations_ForwardActorAndCancellationAndMapRejections(CollectionWriteStatus status, Type responseType)
    {
        using var cancellation = new CancellationTokenSource();
        _controller.HttpContext.RequestAborted = cancellation.Token;
        var request = new UpdateCollectionRequest { Name = "Updated" };
        var rejected = new CollectionWriteResult(status, Error: "Review the collection");
        _details.Setup(service => service.UpdateAsync(TestUserId, TestWorkspaceId, 9, request, cancellation.Token)).ReturnsAsync(rejected);
        _deletion.Setup(service => service.DeleteAsync(TestUserId, TestWorkspaceId, 9, cancellation.Token)).ReturnsAsync(rejected);
        var updated = await _controller.UpdateCollection(9, request);
        var deleted = await _controller.DeleteCollection(9);
        Assert.IsType(responseType, updated.Result);
        Assert.IsType(responseType, deleted);
        if (updated.Result is ObjectResult error) Assert.Equal(rejected.Error, error.Value);
        _details.VerifyAll();
        _deletion.VerifyAll();
        _mockCollectionRepository.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Mutations_ReturnOnlyCommittedResults()
    {
        var request = new UpdateCollectionRequest { Name = "Updated" };
        var collection = new Collection { Id = 9, Name = "Updated", Visibility = Visibility.Private };
        _details.Setup(service => service.UpdateAsync(TestUserId, TestWorkspaceId, 9, request, CancellationToken.None))
            .ReturnsAsync(new CollectionWriteResult(CollectionWriteStatus.Success, collection));
        _deletion.Setup(service => service.DeleteAsync(TestUserId, TestWorkspaceId, 9, CancellationToken.None))
            .ReturnsAsync(new CollectionWriteResult(CollectionWriteStatus.Success));
        Assert.Same(collection, Assert.IsType<OkObjectResult>((await _controller.UpdateCollection(9, request)).Result).Value);
        Assert.IsType<NoContentResult>(await _controller.DeleteCollection(9));
    }

    [Fact]
    public async Task Mutations_RejectUnknownServiceOutcomes()
    {
        _deletion.Setup(service => service.DeleteAsync(TestUserId, TestWorkspaceId, 9, CancellationToken.None))
            .ReturnsAsync(new CollectionWriteResult((CollectionWriteStatus)999));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => _controller.DeleteCollection(9));
    }

    #region SetupCollection Tests

    [Fact]
    public async Task TemplateOperations_RejectMissingOrForeignCollectionsBeforeAccessingTemplates()
    {
        Assert.IsType<NotFoundResult>((await _controller.GetCollectionTemplates(999)).Result);
        Assert.IsType<NotFoundObjectResult>(await _controller.AssociateTemplate(999, 7));
        Assert.IsType<NotFoundObjectResult>(await _controller.DisassociateTemplate(999, 7));
        _mockItemTemplateRepository.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task TemplateMutations_RejectUnavailableTemplatesAndMissingAssociations()
    {
        _mockCollectionRepository.Setup(repository => repository.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(new Collection { Id = 1, WorkspaceId = TestWorkspaceId });
        Assert.IsType<NotFoundObjectResult>(await _controller.AssociateTemplate(1, 7));
        Assert.IsType<NotFoundObjectResult>(await _controller.DisassociateTemplate(1, 7));
        _mockItemTemplateRepository.Verify(repository => repository.GetByIdAsync(7, TestWorkspaceId), Times.Once);
        _mockItemTemplateRepository.Verify(repository => repository.DisassociateFromCollectionAsync(7, 1), Times.Once);
        _mockItemTemplateRepository.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task SetupCollection_ReturnsThemeValidationError()
    {
        var theme = new CollectionTheme { Id = 1 };
        _mockThemeRepository.Setup(repository => repository.GetByIdAsync(1)).ReturnsAsync(theme);
        _mockSetupService.Setup(service => service.CreateAsync(It.IsAny<Collection>(), theme))
            .ThrowsAsync(new InvalidCollectionThemeException("The selected theme contains circular category relationships."));
        var result = await _controller.SetupCollection(new SetupCollectionRequest { Name = "Books", ThemeId = 1 });
        var response = Assert.IsType<BadRequestObjectResult>(result.Result);
        Assert.Contains("circular category relationships", response.Value!.ToString());
    }

    [Fact]
    public async Task SetupCollection_ReturnsBadRequest_WhenThemeNotFound()
    {
        // Arrange
        var request = new SetupCollectionRequest { Name = "Test Collection", ThemeId = 999 };
        _mockThemeRepository.Setup(repo => repo.GetByIdAsync(999))
            .ReturnsAsync((CollectionTheme?)null);

        // Act
        var result = await _controller.SetupCollection(request);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result.Result);
        Assert.Contains("Invalid theme", badRequestResult.Value?.ToString());
    }

    [Fact]
    public async Task SetupCollection_DelegatesThemeAndDefaultsDescription()
    {
        var theme = new CollectionTheme { Id = 1, Name = "Theme" };
        _mockThemeRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(theme);
        var created = new Collection { Id = 42, Name = "New" };
        _mockSetupService.Setup(s => s.CreateAsync(It.IsAny<Collection>(), theme)).ReturnsAsync(created);
        var result = await _controller.SetupCollection(new SetupCollectionRequest { Name = "New", ThemeId = 1 });
        Assert.Same(created, Assert.IsType<CreatedAtActionResult>(result.Result).Value);
        _mockSetupService.Verify(s => s.CreateAsync(It.Is<Collection>(c => c.WorkspaceId == TestWorkspaceId && c.Name == "New" && c.Description == ""), theme), Times.Once);
    }

    #endregion
}
