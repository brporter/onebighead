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
public class CategoriesControllerReorderTests
{
    private readonly Mock<ICategoryRepository> _mockRepository;
    private readonly Mock<ICollectionRepository> _mockCollectionRepository;
    private readonly Mock<IPublishManagerService> _mockVisibilityService;
    private readonly CategoriesController _controller;
    private const int TestWorkspaceId = 1;
    private const int TestCollectionId = 1;

    public CategoriesControllerReorderTests()
    {
        _mockRepository = new Mock<ICategoryRepository>();
        _mockCollectionRepository = new Mock<ICollectionRepository>();
        _mockVisibilityService = new Mock<IPublishManagerService>();
        _controller = new CategoriesController(
            _mockRepository.Object,
            _mockCollectionRepository.Object,
            _mockVisibilityService.Object);

        var claims = new List<Claim>
        {
            new("workspace_id", TestWorkspaceId.ToString()),
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

    [Fact]
    public async Task ReorderCategories_ReturnsOkResult_WithUpdatedCategories()
    {
        // Arrange
        var cat1 = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "A", SortOrder = 0 };
        var cat2 = new Category { Id = 2, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "B", SortOrder = 1 };
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test", Slug = "test" };

        var request = new ReorderCategoriesRequest
        {
            Categories = new List<CategorySortOrderEntry>
            {
                new() { CategoryId = 1, SortOrder = 1 },
                new() { CategoryId = 2, SortOrder = 0 }
            }
        };

        _mockRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(cat1);
        _mockRepository.Setup(r => r.GetByIdAsync(2, TestWorkspaceId)).ReturnsAsync(cat2);
        _mockRepository.Setup(r => r.ReorderAsync(It.IsAny<Dictionary<int, int>>(), TestWorkspaceId)).Returns(Task.CompletedTask);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(TestCollectionId, TestWorkspaceId)).ReturnsAsync(collection);
        _mockRepository.Setup(r => r.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { cat2, cat1 });
        _mockRepository.Setup(r => r.GetTemplateIdsByCategoryAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new Dictionary<int, List<int>>());

        // Act
        var result = await _controller.ReorderCategories(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCategories = Assert.IsAssignableFrom<IEnumerable<CategoryResponse>>(okResult.Value);
        Assert.Equal(2, returnedCategories.Count());
    }

    [Fact]
    public async Task ReorderCategories_ReturnsBadRequest_WhenEmptyCategories()
    {
        // Arrange
        var request = new ReorderCategoriesRequest
        {
            Categories = new List<CategorySortOrderEntry>()
        };

        // Act
        var result = await _controller.ReorderCategories(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    [Fact]
    public async Task ReorderCategories_ReturnsBadRequest_WhenCategoryNotInWorkspace()
    {
        // Arrange
        var request = new ReorderCategoriesRequest
        {
            Categories = new List<CategorySortOrderEntry>
            {
                new() { CategoryId = 999, SortOrder = 0 }
            }
        };

        _mockRepository.Setup(r => r.GetByIdAsync(999, TestWorkspaceId)).ReturnsAsync((Category?)null);

        // Act
        var result = await _controller.ReorderCategories(request);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(result.Result);
        Assert.Contains("999", badRequest.Value?.ToString());
    }

    [Fact]
    public async Task ReorderCategories_ReturnsBadRequest_WhenCategoriesFromDifferentCollections()
    {
        // Arrange
        var cat1 = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = 1, Name = "A" };
        var cat2 = new Category { Id = 2, WorkspaceId = TestWorkspaceId, CollectionId = 2, Name = "B" };

        var request = new ReorderCategoriesRequest
        {
            Categories = new List<CategorySortOrderEntry>
            {
                new() { CategoryId = 1, SortOrder = 1 },
                new() { CategoryId = 2, SortOrder = 0 }
            }
        };

        _mockRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(cat1);
        _mockRepository.Setup(r => r.GetByIdAsync(2, TestWorkspaceId)).ReturnsAsync(cat2);

        // Act
        var result = await _controller.ReorderCategories(request);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(result.Result);
        Assert.Contains("same collection", badRequest.Value?.ToString());
    }

    [Fact]
    public async Task ReorderCategories_CallsReorderAsync_WithCorrectParameters()
    {
        // Arrange
        var cat1 = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "A" };
        var cat2 = new Category { Id = 2, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "B" };
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test", Slug = "test" };

        var request = new ReorderCategoriesRequest
        {
            Categories = new List<CategorySortOrderEntry>
            {
                new() { CategoryId = 1, SortOrder = 1 },
                new() { CategoryId = 2, SortOrder = 0 }
            }
        };

        _mockRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(cat1);
        _mockRepository.Setup(r => r.GetByIdAsync(2, TestWorkspaceId)).ReturnsAsync(cat2);
        _mockRepository.Setup(r => r.ReorderAsync(It.IsAny<Dictionary<int, int>>(), TestWorkspaceId)).Returns(Task.CompletedTask);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(TestCollectionId, TestWorkspaceId)).ReturnsAsync(collection);
        _mockRepository.Setup(r => r.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { cat1, cat2 });
        _mockRepository.Setup(r => r.GetTemplateIdsByCategoryAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new Dictionary<int, List<int>>());

        // Act
        await _controller.ReorderCategories(request);

        // Assert
        _mockRepository.Verify(r => r.ReorderAsync(
            It.Is<Dictionary<int, int>>(d => d[1] == 1 && d[2] == 0),
            TestWorkspaceId), Times.Once);
    }

    [Fact]
    public async Task ReorderCategories_ComputesEffectiveVisibility()
    {
        // Arrange
        var cat1 = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "A" };
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test", Slug = "test" };

        var request = new ReorderCategoriesRequest
        {
            Categories = new List<CategorySortOrderEntry>
            {
                new() { CategoryId = 1, SortOrder = 0 }
            }
        };

        _mockRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(cat1);
        _mockRepository.Setup(r => r.ReorderAsync(It.IsAny<Dictionary<int, int>>(), TestWorkspaceId)).Returns(Task.CompletedTask);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(TestCollectionId, TestWorkspaceId)).ReturnsAsync(collection);
        _mockRepository.Setup(r => r.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { cat1 });
        _mockRepository.Setup(r => r.GetTemplateIdsByCategoryAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new Dictionary<int, List<int>>());

        // Act
        await _controller.ReorderCategories(request);

        // Assert
        _mockVisibilityService.Verify(v => v.ComputeEffectiveVisibility(
            It.IsAny<List<Category>>(), collection), Times.Once);
    }

    [Fact]
    public async Task ReorderCategories_IncludesTemplateIdsInResponse()
    {
        // Arrange
        var cat1 = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "A" };
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test", Slug = "test" };
        var templateIds = new Dictionary<int, List<int>> { { 1, new List<int> { 10, 20 } } };

        var request = new ReorderCategoriesRequest
        {
            Categories = new List<CategorySortOrderEntry>
            {
                new() { CategoryId = 1, SortOrder = 0 }
            }
        };

        _mockRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(cat1);
        _mockRepository.Setup(r => r.ReorderAsync(It.IsAny<Dictionary<int, int>>(), TestWorkspaceId)).Returns(Task.CompletedTask);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(TestCollectionId, TestWorkspaceId)).ReturnsAsync(collection);
        _mockRepository.Setup(r => r.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { cat1 });
        _mockRepository.Setup(r => r.GetTemplateIdsByCategoryAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(templateIds);

        // Act
        var result = await _controller.ReorderCategories(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedCategories = Assert.IsAssignableFrom<IEnumerable<CategoryResponse>>(okResult.Value).ToList();
        Assert.Single(returnedCategories);
        Assert.Equal(new List<int> { 10, 20 }, returnedCategories[0].ItemTemplateIds);
    }

    [Fact]
    public async Task ReorderCategories_WhenCollectionIsNull_DoesNotComputeVisibility()
    {
        // Arrange
        var cat1 = new Category { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "A" };

        var request = new ReorderCategoriesRequest
        {
            Categories = new List<CategorySortOrderEntry>
            {
                new() { CategoryId = 1, SortOrder = 0 }
            }
        };

        _mockRepository.Setup(r => r.GetByIdAsync(1, TestWorkspaceId)).ReturnsAsync(cat1);
        _mockRepository.Setup(r => r.ReorderAsync(It.IsAny<Dictionary<int, int>>(), TestWorkspaceId)).Returns(Task.CompletedTask);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(TestCollectionId, TestWorkspaceId)).ReturnsAsync((Collection?)null);
        _mockRepository.Setup(r => r.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { cat1 });
        _mockRepository.Setup(r => r.GetTemplateIdsByCategoryAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new Dictionary<int, List<int>>());

        // Act
        var result = await _controller.ReorderCategories(request);

        // Assert
        Assert.IsType<OkObjectResult>(result.Result);
        _mockVisibilityService.Verify(v => v.ComputeEffectiveVisibility(
            It.IsAny<List<Category>>(), It.IsAny<Collection>()), Times.Never);
    }
}
