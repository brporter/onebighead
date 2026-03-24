using backend.DTOs;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Security.Claims;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class PublishControllerTests
{
    private readonly Mock<IVisibilityService> _mockVisibilityService;
    private readonly Mock<IItemRepository> _mockItemRepository;
    private readonly Mock<ICategoryRepository> _mockCategoryRepository;
    private readonly Mock<ICollectionRepository> _mockCollectionRepository;
    private readonly Mock<IWorkspaceRepository> _mockWorkspaceRepository;
    private readonly PublishController _controller;
    private const int TestWorkspaceId = 1;
    private const int TestUserId = 1;

    public PublishControllerTests()
    {
        _mockVisibilityService = new Mock<IVisibilityService>();
        _mockItemRepository = new Mock<IItemRepository>();
        _mockCategoryRepository = new Mock<ICategoryRepository>();
        _mockCollectionRepository = new Mock<ICollectionRepository>();
        _mockWorkspaceRepository = new Mock<IWorkspaceRepository>();

        _controller = new PublishController(
            _mockVisibilityService.Object,
            _mockItemRepository.Object,
            _mockCategoryRepository.Object,
            _mockCollectionRepository.Object,
            _mockWorkspaceRepository.Object);

        SetupAuth(TestWorkspaceId, TestUserId);
    }

    private void SetupAuth(int workspaceId, int userId)
    {
        var claims = new List<Claim>
        {
            new("workspace_id", workspaceId.ToString()),
            new("sub", userId.ToString()),
            new(ClaimTypes.NameIdentifier, userId.ToString()),
            new(ClaimTypes.Email, "test@example.com")
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var claimsPrincipal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = claimsPrincipal }
        };
    }

    #region PublishItem Tests

    [Fact]
    public async Task PublishItem_ValidItem_ReturnsOkWithPublishResponse()
    {
        // Arrange
        var item = new Item { Id = 10, Name = "Test Item", CollectionId = 1, CategoryId = 2, WorkspaceId = TestWorkspaceId };
        var collection = new Collection { Id = 1, Name = "Test Collection", WorkspaceId = TestWorkspaceId };
        var category = new Category { Id = 2, Name = "Test Category", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        var workspace = new Workspace { Id = TestWorkspaceId, Slug = "my-workspace" };

        _mockItemRepository.Setup(r => r.GetByIdAsync(10, TestWorkspaceId)).ReturnsAsync(item);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(2, TestWorkspaceId)).ReturnsAsync(category);
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId)).ReturnsAsync(workspace);

        var publishResult = new PublishResult
        {
            Published = new OneBigHead.Server.Services.PublishedEntityInfo { Type = "item", Id = 10, Name = "Test Item" },
            Promoted = new List<OneBigHead.Server.Services.PublishedEntityInfo>
            {
                new() { Type = "collection", Id = 1, Name = "Test Collection" }
            }
        };
        _mockVisibilityService.Setup(s => s.PublishItem(item, collection, category)).Returns(publishResult);
        _mockVisibilityService.Setup(s => s.RequiresSlugSetup(workspace)).Returns(false);

        // Act
        var result = await _controller.PublishItem(TestWorkspaceId, 10);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PublishResponse>(okResult.Value);
        Assert.Equal("item", response.Published.Type);
        Assert.Equal(10, response.Published.Id);
        Assert.Single(response.Promoted);
        Assert.Equal("collection", response.Promoted[0].Type);
        Assert.False(response.RequiresSlugSetup);

        _mockItemRepository.Verify(r => r.UpdateAsync(10, item, TestWorkspaceId), Times.Once);
        _mockCollectionRepository.Verify(r => r.UpdateAsync(1, collection, TestWorkspaceId), Times.Once);
        _mockCategoryRepository.Verify(r => r.UpdateAsync(2, category, TestWorkspaceId), Times.Once);
    }

    [Fact]
    public async Task PublishItem_ItemNotFound_ReturnsNotFound()
    {
        // Arrange
        _mockItemRepository.Setup(r => r.GetByIdAsync(10, TestWorkspaceId)).ReturnsAsync((Item?)null);

        // Act
        var result = await _controller.PublishItem(TestWorkspaceId, 10);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task PublishItem_CollectionNotFound_ReturnsNotFound()
    {
        // Arrange
        var item = new Item { Id = 10, Name = "Test Item", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        _mockItemRepository.Setup(r => r.GetByIdAsync(10, TestWorkspaceId)).ReturnsAsync(item);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.PublishItem(TestWorkspaceId, 10);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task PublishItem_WorkspaceNotFound_ReturnsNotFound()
    {
        // Arrange
        var item = new Item { Id = 10, Name = "Test Item", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        var collection = new Collection { Id = 1, Name = "Test Collection", WorkspaceId = TestWorkspaceId };
        _mockItemRepository.Setup(r => r.GetByIdAsync(10, TestWorkspaceId)).ReturnsAsync(item);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(collection);
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId)).ReturnsAsync((Workspace?)null);

        // Act
        var result = await _controller.PublishItem(TestWorkspaceId, 10);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task PublishItem_RequiresSlugSetup_ReturnsResponseWithTrue()
    {
        // Arrange
        var item = new Item { Id = 10, Name = "Test Item", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        var collection = new Collection { Id = 1, Name = "Test Collection", WorkspaceId = TestWorkspaceId };
        var workspace = new Workspace { Id = TestWorkspaceId, Slug = null };

        _mockItemRepository.Setup(r => r.GetByIdAsync(10, TestWorkspaceId)).ReturnsAsync(item);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(collection);
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId)).ReturnsAsync(workspace);

        var publishResult = new PublishResult
        {
            Published = new OneBigHead.Server.Services.PublishedEntityInfo { Type = "item", Id = 10, Name = "Test Item" }
        };
        _mockVisibilityService.Setup(s => s.PublishItem(item, collection, null)).Returns(publishResult);
        _mockVisibilityService.Setup(s => s.RequiresSlugSetup(workspace)).Returns(true);

        // Act
        var result = await _controller.PublishItem(TestWorkspaceId, 10);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PublishResponse>(okResult.Value);
        Assert.True(response.RequiresSlugSetup);
    }

    [Fact]
    public async Task PublishItem_ItemWithNoCategory_SkipsCategoryUpdate()
    {
        // Arrange
        var item = new Item { Id = 10, Name = "Test Item", CollectionId = 1, CategoryId = null, WorkspaceId = TestWorkspaceId };
        var collection = new Collection { Id = 1, Name = "Test Collection", WorkspaceId = TestWorkspaceId };
        var workspace = new Workspace { Id = TestWorkspaceId, Slug = "slug" };

        _mockItemRepository.Setup(r => r.GetByIdAsync(10, TestWorkspaceId)).ReturnsAsync(item);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(collection);
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId)).ReturnsAsync(workspace);

        var publishResult = new PublishResult
        {
            Published = new OneBigHead.Server.Services.PublishedEntityInfo { Type = "item", Id = 10, Name = "Test Item" }
        };
        _mockVisibilityService.Setup(s => s.PublishItem(item, collection, null)).Returns(publishResult);
        _mockVisibilityService.Setup(s => s.RequiresSlugSetup(workspace)).Returns(false);

        // Act
        var result = await _controller.PublishItem(TestWorkspaceId, 10);

        // Assert
        Assert.IsType<OkObjectResult>(result);
        _mockCategoryRepository.Verify(r => r.UpdateAsync(It.IsAny<int>(), It.IsAny<Category>(), It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task PublishItem_WrongWorkspaceId_ReturnsForbid()
    {
        // Act
        var result = await _controller.PublishItem(999, 10);

        // Assert
        Assert.IsType<ForbidResult>(result);
    }

    #endregion

    #region UnpublishItem Tests

    [Fact]
    public async Task UnpublishItem_ValidItem_ReturnsOkWithUnpublishResponse()
    {
        // Arrange
        var item = new Item { Id = 10, Name = "Test Item", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        _mockItemRepository.Setup(r => r.GetByIdAsync(10, TestWorkspaceId)).ReturnsAsync(item);

        // Act
        var result = await _controller.UnpublishItem(TestWorkspaceId, 10);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<UnpublishResponse>(okResult.Value);
        Assert.Equal("item", response.Unpublished.Type);
        Assert.Equal(10, response.Unpublished.Id);
        Assert.Equal("Test Item", response.Unpublished.Name);
        Assert.Equal(0, response.AffectedPublicItems);
        Assert.Equal(0, response.AffectedPublicCategories);

        _mockVisibilityService.Verify(s => s.UnpublishEntity(item), Times.Once);
        _mockItemRepository.Verify(r => r.UpdateAsync(10, item, TestWorkspaceId), Times.Once);
    }

    [Fact]
    public async Task UnpublishItem_ItemNotFound_ReturnsNotFound()
    {
        // Arrange
        _mockItemRepository.Setup(r => r.GetByIdAsync(10, TestWorkspaceId)).ReturnsAsync((Item?)null);

        // Act
        var result = await _controller.UnpublishItem(TestWorkspaceId, 10);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task UnpublishItem_WrongWorkspaceId_ReturnsForbid()
    {
        // Act
        var result = await _controller.UnpublishItem(999, 10);

        // Assert
        Assert.IsType<ForbidResult>(result);
    }

    #endregion

    #region PublishCategory Tests

    [Fact]
    public async Task PublishCategory_WithIncludeChildren_ReturnsOkWithChildrenPublished()
    {
        // Arrange
        var category = new Category { Id = 5, Name = "Test Cat", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        var collection = new Collection { Id = 1, Name = "Test Collection", WorkspaceId = TestWorkspaceId };
        var allCategories = new List<Category> { category };
        var items = new List<Item>();
        var workspace = new Workspace { Id = TestWorkspaceId, Slug = "slug" };

        _mockCategoryRepository.Setup(r => r.GetByIdAsync(5, TestWorkspaceId)).ReturnsAsync(category);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, TestWorkspaceId)).ReturnsAsync(allCategories);
        _mockItemRepository.Setup(r => r.GetByCollectionIdAsync(1, TestWorkspaceId)).ReturnsAsync(items);
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId)).ReturnsAsync(workspace);

        var publishResult = new PublishResult
        {
            Published = new OneBigHead.Server.Services.PublishedEntityInfo { Type = "category", Id = 5, Name = "Test Cat" },
            ChildrenPublished = 3
        };
        _mockVisibilityService.Setup(s => s.PublishCategory(category, collection, items, allCategories, true)).Returns(publishResult);
        _mockVisibilityService.Setup(s => s.RequiresSlugSetup(workspace)).Returns(false);

        var request = new PublishCategoryRequest { IncludeChildren = true };

        // Act
        var result = await _controller.PublishCategory(TestWorkspaceId, 5, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PublishResponse>(okResult.Value);
        Assert.Equal("category", response.Published.Type);
        Assert.Equal(3, response.ChildrenPublished);
    }

    [Fact]
    public async Task PublishCategory_WithoutIncludeChildren_ReturnsOkCategoryOnly()
    {
        // Arrange
        var category = new Category { Id = 5, Name = "Test Cat", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        var collection = new Collection { Id = 1, Name = "Test Collection", WorkspaceId = TestWorkspaceId };
        var allCategories = new List<Category> { category };
        var items = new List<Item>();
        var workspace = new Workspace { Id = TestWorkspaceId, Slug = "slug" };

        _mockCategoryRepository.Setup(r => r.GetByIdAsync(5, TestWorkspaceId)).ReturnsAsync(category);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, TestWorkspaceId)).ReturnsAsync(allCategories);
        _mockItemRepository.Setup(r => r.GetByCollectionIdAsync(1, TestWorkspaceId)).ReturnsAsync(items);
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId)).ReturnsAsync(workspace);

        var publishResult = new PublishResult
        {
            Published = new OneBigHead.Server.Services.PublishedEntityInfo { Type = "category", Id = 5, Name = "Test Cat" },
            ChildrenPublished = 0
        };
        _mockVisibilityService.Setup(s => s.PublishCategory(category, collection, items, allCategories, false)).Returns(publishResult);
        _mockVisibilityService.Setup(s => s.RequiresSlugSetup(workspace)).Returns(false);

        var request = new PublishCategoryRequest { IncludeChildren = false };

        // Act
        var result = await _controller.PublishCategory(TestWorkspaceId, 5, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PublishResponse>(okResult.Value);
        Assert.Equal(0, response.ChildrenPublished);
    }

    [Fact]
    public async Task PublishCategory_CategoryNotFound_ReturnsNotFound()
    {
        // Arrange
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(5, TestWorkspaceId)).ReturnsAsync((Category?)null);
        var request = new PublishCategoryRequest { IncludeChildren = false };

        // Act
        var result = await _controller.PublishCategory(TestWorkspaceId, 5, request);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task PublishCategory_CollectionNotFound_ReturnsNotFound()
    {
        // Arrange
        var category = new Category { Id = 5, Name = "Test Cat", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(5, TestWorkspaceId)).ReturnsAsync(category);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync((Collection?)null);
        var request = new PublishCategoryRequest { IncludeChildren = false };

        // Act
        var result = await _controller.PublishCategory(TestWorkspaceId, 5, request);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task PublishCategory_WorkspaceNotFound_ReturnsNotFound()
    {
        // Arrange
        var category = new Category { Id = 5, Name = "Test Cat", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        var collection = new Collection { Id = 1, Name = "Test Collection", WorkspaceId = TestWorkspaceId };
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(5, TestWorkspaceId)).ReturnsAsync(category);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, TestWorkspaceId)).ReturnsAsync(new List<Category> { category });
        _mockItemRepository.Setup(r => r.GetByCollectionIdAsync(1, TestWorkspaceId)).ReturnsAsync(new List<Item>());
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId)).ReturnsAsync((Workspace?)null);
        var request = new PublishCategoryRequest { IncludeChildren = false };

        // Act
        var result = await _controller.PublishCategory(TestWorkspaceId, 5, request);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task PublishCategory_WrongWorkspaceId_ReturnsForbid()
    {
        var request = new PublishCategoryRequest { IncludeChildren = false };

        // Act
        var result = await _controller.PublishCategory(999, 5, request);

        // Assert
        Assert.IsType<ForbidResult>(result);
    }

    [Fact]
    public async Task PublishCategory_PersistsAllChanges()
    {
        // Arrange
        var category = new Category { Id = 5, Name = "Test Cat", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        var childCategory = new Category { Id = 6, Name = "Child Cat", CollectionId = 1, WorkspaceId = TestWorkspaceId, ParentCategoryId = 5 };
        var collection = new Collection { Id = 1, Name = "Test Collection", WorkspaceId = TestWorkspaceId };
        var allCategories = new List<Category> { category, childCategory };
        var item = new Item { Id = 20, Name = "Test Item", CollectionId = 1, CategoryId = 5, WorkspaceId = TestWorkspaceId };
        var items = new List<Item> { item };
        var workspace = new Workspace { Id = TestWorkspaceId, Slug = "slug" };

        _mockCategoryRepository.Setup(r => r.GetByIdAsync(5, TestWorkspaceId)).ReturnsAsync(category);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, TestWorkspaceId)).ReturnsAsync(allCategories);
        _mockItemRepository.Setup(r => r.GetByCollectionIdAsync(1, TestWorkspaceId)).ReturnsAsync(items);
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId)).ReturnsAsync(workspace);

        var publishResult = new PublishResult
        {
            Published = new OneBigHead.Server.Services.PublishedEntityInfo { Type = "category", Id = 5, Name = "Test Cat" }
        };
        _mockVisibilityService.Setup(s => s.PublishCategory(category, collection, items, allCategories, true)).Returns(publishResult);
        _mockVisibilityService.Setup(s => s.RequiresSlugSetup(workspace)).Returns(false);

        var request = new PublishCategoryRequest { IncludeChildren = true };

        // Act
        await _controller.PublishCategory(TestWorkspaceId, 5, request);

        // Assert - verify all entities are persisted
        _mockCollectionRepository.Verify(r => r.UpdateAsync(1, collection, TestWorkspaceId), Times.Once);
        _mockCategoryRepository.Verify(r => r.UpdateAsync(5, category, TestWorkspaceId), Times.Once);
        _mockCategoryRepository.Verify(r => r.UpdateAsync(6, childCategory, TestWorkspaceId), Times.Once);
        _mockItemRepository.Verify(r => r.UpdateAsync(20, item, TestWorkspaceId), Times.Once);
    }

    #endregion

    #region UnpublishCategory Tests

    [Fact]
    public async Task UnpublishCategory_ValidCategory_ReturnsOkWithPreview()
    {
        // Arrange
        var category = new Category { Id = 5, Name = "Test Cat", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        var collection = new Collection { Id = 1, Name = "Test Collection", WorkspaceId = TestWorkspaceId };
        var childCategory = new Category { Id = 6, Name = "Child", CollectionId = 1, WorkspaceId = TestWorkspaceId, ParentCategoryId = 5 };
        var allCategories = new List<Category> { category, childCategory };
        var items = new List<Item> { new() { Id = 20, Name = "Item", CollectionId = 1, CategoryId = 5, WorkspaceId = TestWorkspaceId } };

        _mockCategoryRepository.Setup(r => r.GetByIdAsync(5, TestWorkspaceId)).ReturnsAsync(category);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, TestWorkspaceId)).ReturnsAsync(allCategories);
        _mockItemRepository.Setup(r => r.GetByCollectionIdAsync(1, TestWorkspaceId)).ReturnsAsync(items);

        var preview = new UnpublishPreview { AffectedPublicItems = 2, AffectedPublicCategories = 1 };
        _mockVisibilityService.Setup(s => s.GetUnpublishPreview(
            category,
            items,
            It.Is<IEnumerable<Category>>(cats => !cats.Any(c => c.Id == 5)),
            collection)).Returns(preview);

        // Act
        var result = await _controller.UnpublishCategory(TestWorkspaceId, 5);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<UnpublishResponse>(okResult.Value);
        Assert.Equal("category", response.Unpublished.Type);
        Assert.Equal(5, response.Unpublished.Id);
        Assert.Equal(2, response.AffectedPublicItems);
        Assert.Equal(1, response.AffectedPublicCategories);

        _mockVisibilityService.Verify(s => s.UnpublishEntity(category), Times.Once);
        _mockCategoryRepository.Verify(r => r.UpdateAsync(5, category, TestWorkspaceId), Times.Once);
    }

    [Fact]
    public async Task UnpublishCategory_CategoryNotFound_ReturnsNotFound()
    {
        // Arrange
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(5, TestWorkspaceId)).ReturnsAsync((Category?)null);

        // Act
        var result = await _controller.UnpublishCategory(TestWorkspaceId, 5);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task UnpublishCategory_CollectionNotFound_ReturnsNotFound()
    {
        // Arrange
        var category = new Category { Id = 5, Name = "Test Cat", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(5, TestWorkspaceId)).ReturnsAsync(category);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.UnpublishCategory(TestWorkspaceId, 5);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task UnpublishCategory_WrongWorkspaceId_ReturnsForbid()
    {
        // Act
        var result = await _controller.UnpublishCategory(999, 5);

        // Assert
        Assert.IsType<ForbidResult>(result);
    }

    #endregion

    #region GetCategoryUnpublishPreview Tests

    [Fact]
    public async Task GetCategoryUnpublishPreview_ValidCategory_ReturnsPreview()
    {
        // Arrange
        var category = new Category { Id = 5, Name = "Test Cat", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        var collection = new Collection { Id = 1, Name = "Test Collection", WorkspaceId = TestWorkspaceId };
        var childCategory = new Category { Id = 6, Name = "Child", CollectionId = 1, WorkspaceId = TestWorkspaceId, ParentCategoryId = 5 };
        var allCategories = new List<Category> { category, childCategory };
        var items = new List<Item> { new() { Id = 20, Name = "Item", CollectionId = 1, CategoryId = 5, WorkspaceId = TestWorkspaceId } };

        _mockCategoryRepository.Setup(r => r.GetByIdAsync(5, TestWorkspaceId)).ReturnsAsync(category);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, TestWorkspaceId)).ReturnsAsync(allCategories);
        _mockItemRepository.Setup(r => r.GetByCollectionIdAsync(1, TestWorkspaceId)).ReturnsAsync(items);

        var preview = new UnpublishPreview { AffectedPublicItems = 3, AffectedPublicCategories = 2 };
        _mockVisibilityService.Setup(s => s.GetUnpublishPreview(
            category,
            items,
            It.Is<IEnumerable<Category>>(cats => !cats.Any(c => c.Id == 5)),
            collection)).Returns(preview);

        // Act
        var result = await _controller.GetCategoryUnpublishPreview(TestWorkspaceId, 5);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<UnpublishPreviewResponse>(okResult.Value);
        Assert.Equal(3, response.AffectedPublicItems);
        Assert.Equal(2, response.AffectedPublicCategories);
    }

    [Fact]
    public async Task GetCategoryUnpublishPreview_CategoryNotFound_ReturnsNotFound()
    {
        // Arrange
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(5, TestWorkspaceId)).ReturnsAsync((Category?)null);

        // Act
        var result = await _controller.GetCategoryUnpublishPreview(TestWorkspaceId, 5);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task GetCategoryUnpublishPreview_CollectionNotFound_ReturnsNotFound()
    {
        // Arrange
        var category = new Category { Id = 5, Name = "Test Cat", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(5, TestWorkspaceId)).ReturnsAsync(category);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.GetCategoryUnpublishPreview(TestWorkspaceId, 5);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task GetCategoryUnpublishPreview_WrongWorkspaceId_ReturnsForbid()
    {
        // Act
        var result = await _controller.GetCategoryUnpublishPreview(999, 5);

        // Assert
        Assert.IsType<ForbidResult>(result);
    }

    #endregion

    #region PublishCollection Tests

    [Fact]
    public async Task PublishCollection_ValidCollection_ReturnsOk()
    {
        // Arrange
        var collection = new Collection { Id = 1, Name = "Test Collection", WorkspaceId = TestWorkspaceId };
        var categories = new List<Category>();
        var items = new List<Item>();
        var workspace = new Workspace { Id = TestWorkspaceId, Slug = "slug" };

        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, TestWorkspaceId)).ReturnsAsync(categories);
        _mockItemRepository.Setup(r => r.GetByCollectionIdAsync(1, TestWorkspaceId)).ReturnsAsync(items);
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId)).ReturnsAsync(workspace);

        var publishResult = new PublishResult
        {
            Published = new OneBigHead.Server.Services.PublishedEntityInfo { Type = "collection", Id = 1, Name = "Test Collection" },
            ChildrenPublished = 0
        };
        _mockVisibilityService.Setup(s => s.PublishCollection(collection, categories, items, false)).Returns(publishResult);
        _mockVisibilityService.Setup(s => s.RequiresSlugSetup(workspace)).Returns(false);

        var request = new PublishCollectionRequest { IncludeChildren = false };

        // Act
        var result = await _controller.PublishCollection(TestWorkspaceId, 1, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PublishResponse>(okResult.Value);
        Assert.Equal("collection", response.Published.Type);
        Assert.Equal(1, response.Published.Id);
        Assert.False(response.RequiresSlugSetup);

        _mockCollectionRepository.Verify(r => r.UpdateAsync(1, collection, TestWorkspaceId), Times.Once);
    }

    [Fact]
    public async Task PublishCollection_CollectionNotFound_ReturnsNotFound()
    {
        // Arrange
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync((Collection?)null);
        var request = new PublishCollectionRequest { IncludeChildren = false };

        // Act
        var result = await _controller.PublishCollection(TestWorkspaceId, 1, request);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task PublishCollection_WorkspaceNotFound_ReturnsNotFound()
    {
        // Arrange
        var collection = new Collection { Id = 1, Name = "Test Collection", WorkspaceId = TestWorkspaceId };
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, TestWorkspaceId)).ReturnsAsync(new List<Category>());
        _mockItemRepository.Setup(r => r.GetByCollectionIdAsync(1, TestWorkspaceId)).ReturnsAsync(new List<Item>());
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId)).ReturnsAsync((Workspace?)null);
        var request = new PublishCollectionRequest { IncludeChildren = false };

        // Act
        var result = await _controller.PublishCollection(TestWorkspaceId, 1, request);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task PublishCollection_WrongWorkspaceId_ReturnsForbid()
    {
        var request = new PublishCollectionRequest { IncludeChildren = false };

        // Act
        var result = await _controller.PublishCollection(999, 1, request);

        // Assert
        Assert.IsType<ForbidResult>(result);
    }

    [Fact]
    public async Task PublishCollection_PersistsAllCategoriesAndItems()
    {
        // Arrange
        var collection = new Collection { Id = 1, Name = "Test Collection", WorkspaceId = TestWorkspaceId };
        var cat1 = new Category { Id = 5, Name = "Cat 1", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        var cat2 = new Category { Id = 6, Name = "Cat 2", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        var categories = new List<Category> { cat1, cat2 };
        var item1 = new Item { Id = 10, Name = "Item 1", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        var items = new List<Item> { item1 };
        var workspace = new Workspace { Id = TestWorkspaceId, Slug = "slug" };

        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, TestWorkspaceId)).ReturnsAsync(categories);
        _mockItemRepository.Setup(r => r.GetByCollectionIdAsync(1, TestWorkspaceId)).ReturnsAsync(items);
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId)).ReturnsAsync(workspace);

        var publishResult = new PublishResult
        {
            Published = new OneBigHead.Server.Services.PublishedEntityInfo { Type = "collection", Id = 1, Name = "Test Collection" },
            ChildrenPublished = 3
        };
        _mockVisibilityService.Setup(s => s.PublishCollection(collection, categories, items, true)).Returns(publishResult);
        _mockVisibilityService.Setup(s => s.RequiresSlugSetup(workspace)).Returns(false);

        var request = new PublishCollectionRequest { IncludeChildren = true };

        // Act
        await _controller.PublishCollection(TestWorkspaceId, 1, request);

        // Assert
        _mockCollectionRepository.Verify(r => r.UpdateAsync(1, collection, TestWorkspaceId), Times.Once);
        _mockCategoryRepository.Verify(r => r.UpdateAsync(5, cat1, TestWorkspaceId), Times.Once);
        _mockCategoryRepository.Verify(r => r.UpdateAsync(6, cat2, TestWorkspaceId), Times.Once);
        _mockItemRepository.Verify(r => r.UpdateAsync(10, item1, TestWorkspaceId), Times.Once);
    }

    #endregion

    #region UnpublishCollection Tests

    [Fact]
    public async Task UnpublishCollection_ValidCollection_ReturnsOkWithPreview()
    {
        // Arrange
        var collection = new Collection { Id = 1, Name = "Test Collection", WorkspaceId = TestWorkspaceId };
        var categories = new List<Category>();
        var items = new List<Item>();

        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, TestWorkspaceId)).ReturnsAsync(categories);
        _mockItemRepository.Setup(r => r.GetByCollectionIdAsync(1, TestWorkspaceId)).ReturnsAsync(items);

        var preview = new UnpublishPreview { AffectedPublicItems = 5, AffectedPublicCategories = 2 };
        _mockVisibilityService.Setup(s => s.GetUnpublishPreviewForCollection(collection, categories, items)).Returns(preview);

        // Act
        var result = await _controller.UnpublishCollection(TestWorkspaceId, 1);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<UnpublishResponse>(okResult.Value);
        Assert.Equal("collection", response.Unpublished.Type);
        Assert.Equal(1, response.Unpublished.Id);
        Assert.Equal(5, response.AffectedPublicItems);
        Assert.Equal(2, response.AffectedPublicCategories);

        _mockVisibilityService.Verify(s => s.UnpublishEntity(collection), Times.Once);
        _mockCollectionRepository.Verify(r => r.UpdateAsync(1, collection, TestWorkspaceId), Times.Once);
    }

    [Fact]
    public async Task UnpublishCollection_CollectionNotFound_ReturnsNotFound()
    {
        // Arrange
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.UnpublishCollection(TestWorkspaceId, 1);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task UnpublishCollection_WrongWorkspaceId_ReturnsForbid()
    {
        // Act
        var result = await _controller.UnpublishCollection(999, 1);

        // Assert
        Assert.IsType<ForbidResult>(result);
    }

    #endregion

    #region GetCollectionUnpublishPreview Tests

    [Fact]
    public async Task GetCollectionUnpublishPreview_ValidCollection_ReturnsPreview()
    {
        // Arrange
        var collection = new Collection { Id = 1, Name = "Test Collection", WorkspaceId = TestWorkspaceId };
        var categories = new List<Category>();
        var items = new List<Item>();

        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, TestWorkspaceId)).ReturnsAsync(categories);
        _mockItemRepository.Setup(r => r.GetByCollectionIdAsync(1, TestWorkspaceId)).ReturnsAsync(items);

        var preview = new UnpublishPreview { AffectedPublicItems = 10, AffectedPublicCategories = 3 };
        _mockVisibilityService.Setup(s => s.GetUnpublishPreviewForCollection(collection, categories, items)).Returns(preview);

        // Act
        var result = await _controller.GetCollectionUnpublishPreview(TestWorkspaceId, 1);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<UnpublishPreviewResponse>(okResult.Value);
        Assert.Equal(10, response.AffectedPublicItems);
        Assert.Equal(3, response.AffectedPublicCategories);
    }

    [Fact]
    public async Task GetCollectionUnpublishPreview_CollectionNotFound_ReturnsNotFound()
    {
        // Arrange
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.GetCollectionUnpublishPreview(TestWorkspaceId, 1);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task GetCollectionUnpublishPreview_WrongWorkspaceId_ReturnsForbid()
    {
        // Act
        var result = await _controller.GetCollectionUnpublishPreview(999, 1);

        // Assert
        Assert.IsType<ForbidResult>(result);
    }

    #endregion

    #region BulkPublishItems Tests

    [Fact]
    public async Task BulkPublishItems_ValidItems_ReturnsOkWithCounts()
    {
        // Arrange
        var workspace = new Workspace { Id = TestWorkspaceId, Slug = "slug" };
        var item1 = new Item { Id = 10, Name = "Item 1", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        var item2 = new Item { Id = 11, Name = "Item 2", CollectionId = 1, CategoryId = 5, WorkspaceId = TestWorkspaceId };
        var collection = new Collection { Id = 1, Name = "Collection", WorkspaceId = TestWorkspaceId };
        var category = new Category { Id = 5, Name = "Category", CollectionId = 1, WorkspaceId = TestWorkspaceId };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId)).ReturnsAsync(workspace);
        _mockItemRepository.Setup(r => r.GetByIdAsync(10, TestWorkspaceId)).ReturnsAsync(item1);
        _mockItemRepository.Setup(r => r.GetByIdAsync(11, TestWorkspaceId)).ReturnsAsync(item2);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(5, TestWorkspaceId)).ReturnsAsync(category);

        var result1 = new PublishResult
        {
            Published = new OneBigHead.Server.Services.PublishedEntityInfo { Type = "item", Id = 10, Name = "Item 1" },
            Promoted = new List<OneBigHead.Server.Services.PublishedEntityInfo>
            {
                new() { Type = "collection", Id = 1, Name = "Collection" }
            }
        };
        var result2 = new PublishResult
        {
            Published = new OneBigHead.Server.Services.PublishedEntityInfo { Type = "item", Id = 11, Name = "Item 2" },
            Promoted = new List<OneBigHead.Server.Services.PublishedEntityInfo>
            {
                new() { Type = "collection", Id = 1, Name = "Collection" }, // duplicate - should be deduplicated
                new() { Type = "category", Id = 5, Name = "Category" }
            }
        };

        _mockVisibilityService.Setup(s => s.PublishItem(item1, collection, null)).Returns(result1);
        _mockVisibilityService.Setup(s => s.PublishItem(item2, collection, category)).Returns(result2);
        _mockVisibilityService.Setup(s => s.RequiresSlugSetup(workspace)).Returns(false);

        var request = new BulkPublishRequest { ItemIds = new List<int> { 10, 11 } };

        // Act
        var result = await _controller.BulkPublishItems(TestWorkspaceId, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<BulkPublishResponse>(okResult.Value);
        Assert.Equal(2, response.PublishedCount);
        Assert.Equal(2, response.Promoted.Count); // collection + category (no duplicate collection)
        Assert.False(response.RequiresSlugSetup);
    }

    [Fact]
    public async Task BulkPublishItems_EmptyItemIds_ReturnsBadRequest()
    {
        // Arrange
        var request = new BulkPublishRequest { ItemIds = new List<int>() };

        // Act
        var result = await _controller.BulkPublishItems(TestWorkspaceId, request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task BulkPublishItems_WorkspaceNotFound_ReturnsNotFound()
    {
        // Arrange
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId)).ReturnsAsync((Workspace?)null);
        var request = new BulkPublishRequest { ItemIds = new List<int> { 10 } };

        // Act
        var result = await _controller.BulkPublishItems(TestWorkspaceId, request);

        // Assert
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task BulkPublishItems_ItemNotFound_SkipsItem()
    {
        // Arrange
        var workspace = new Workspace { Id = TestWorkspaceId, Slug = "slug" };
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId)).ReturnsAsync(workspace);
        _mockItemRepository.Setup(r => r.GetByIdAsync(10, TestWorkspaceId)).ReturnsAsync((Item?)null);
        _mockVisibilityService.Setup(s => s.RequiresSlugSetup(workspace)).Returns(false);

        var request = new BulkPublishRequest { ItemIds = new List<int> { 10 } };

        // Act
        var result = await _controller.BulkPublishItems(TestWorkspaceId, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<BulkPublishResponse>(okResult.Value);
        Assert.Equal(0, response.PublishedCount);
    }

    [Fact]
    public async Task BulkPublishItems_CollectionNotFound_SkipsItem()
    {
        // Arrange
        var workspace = new Workspace { Id = TestWorkspaceId, Slug = "slug" };
        var item = new Item { Id = 10, Name = "Item", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId)).ReturnsAsync(workspace);
        _mockItemRepository.Setup(r => r.GetByIdAsync(10, TestWorkspaceId)).ReturnsAsync(item);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync((Collection?)null);
        _mockVisibilityService.Setup(s => s.RequiresSlugSetup(workspace)).Returns(false);

        var request = new BulkPublishRequest { ItemIds = new List<int> { 10 } };

        // Act
        var result = await _controller.BulkPublishItems(TestWorkspaceId, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<BulkPublishResponse>(okResult.Value);
        Assert.Equal(0, response.PublishedCount);
    }

    [Fact]
    public async Task BulkPublishItems_RequiresSlugSetup_ReturnsTrue()
    {
        // Arrange
        var workspace = new Workspace { Id = TestWorkspaceId, Slug = null };
        var item = new Item { Id = 10, Name = "Item", CollectionId = 1, WorkspaceId = TestWorkspaceId };
        var collection = new Collection { Id = 1, Name = "Collection", WorkspaceId = TestWorkspaceId };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(TestWorkspaceId)).ReturnsAsync(workspace);
        _mockItemRepository.Setup(r => r.GetByIdAsync(10, TestWorkspaceId)).ReturnsAsync(item);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(collection);

        var publishResult = new PublishResult
        {
            Published = new OneBigHead.Server.Services.PublishedEntityInfo { Type = "item", Id = 10, Name = "Item" }
        };
        _mockVisibilityService.Setup(s => s.PublishItem(item, collection, null)).Returns(publishResult);
        _mockVisibilityService.Setup(s => s.RequiresSlugSetup(workspace)).Returns(true);

        var request = new BulkPublishRequest { ItemIds = new List<int> { 10 } };

        // Act
        var result = await _controller.BulkPublishItems(TestWorkspaceId, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<BulkPublishResponse>(okResult.Value);
        Assert.True(response.RequiresSlugSetup);
    }

    [Fact]
    public async Task BulkPublishItems_WrongWorkspaceId_ReturnsForbid()
    {
        var request = new BulkPublishRequest { ItemIds = new List<int> { 10 } };

        // Act
        var result = await _controller.BulkPublishItems(999, request);

        // Assert
        Assert.IsType<ForbidResult>(result);
    }

    #endregion

    #region BulkUnpublishItems Tests

    [Fact]
    public async Task BulkUnpublishItems_ValidItems_ReturnsOkWithCount()
    {
        // Arrange
        var item1 = new Item { Id = 10, Name = "Item 1", WorkspaceId = TestWorkspaceId };
        var item2 = new Item { Id = 11, Name = "Item 2", WorkspaceId = TestWorkspaceId };

        _mockItemRepository.Setup(r => r.GetByIdAsync(10, TestWorkspaceId)).ReturnsAsync(item1);
        _mockItemRepository.Setup(r => r.GetByIdAsync(11, TestWorkspaceId)).ReturnsAsync(item2);

        var request = new BulkUnpublishRequest { ItemIds = new List<int> { 10, 11 } };

        // Act
        var result = await _controller.BulkUnpublishItems(TestWorkspaceId, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<BulkUnpublishResponse>(okResult.Value);
        Assert.Equal(2, response.UnpublishedCount);

        _mockVisibilityService.Verify(s => s.UnpublishEntity(item1), Times.Once);
        _mockVisibilityService.Verify(s => s.UnpublishEntity(item2), Times.Once);
        _mockItemRepository.Verify(r => r.UpdateAsync(10, item1, TestWorkspaceId), Times.Once);
        _mockItemRepository.Verify(r => r.UpdateAsync(11, item2, TestWorkspaceId), Times.Once);
    }

    [Fact]
    public async Task BulkUnpublishItems_EmptyItemIds_ReturnsBadRequest()
    {
        // Arrange
        var request = new BulkUnpublishRequest { ItemIds = new List<int>() };

        // Act
        var result = await _controller.BulkUnpublishItems(TestWorkspaceId, request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task BulkUnpublishItems_ItemNotFound_SkipsItem()
    {
        // Arrange
        _mockItemRepository.Setup(r => r.GetByIdAsync(10, TestWorkspaceId)).ReturnsAsync((Item?)null);

        var request = new BulkUnpublishRequest { ItemIds = new List<int> { 10 } };

        // Act
        var result = await _controller.BulkUnpublishItems(TestWorkspaceId, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<BulkUnpublishResponse>(okResult.Value);
        Assert.Equal(0, response.UnpublishedCount);
    }

    [Fact]
    public async Task BulkUnpublishItems_WrongWorkspaceId_ReturnsForbid()
    {
        var request = new BulkUnpublishRequest { ItemIds = new List<int> { 10 } };

        // Act
        var result = await _controller.BulkUnpublishItems(999, request);

        // Assert
        Assert.IsType<ForbidResult>(result);
    }

    #endregion
}
