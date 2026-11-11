using OneBigHead.Server.Controllers;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using OneBigHead.Server.Services.BulkUpdate;
using OneBigHead.Server.Services.Items;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Security.Claims;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class ItemsControllerTests
{
    private readonly Mock<IItemReadService> _mockItemReads = new();
    private readonly Mock<IItemRepository> _mockItemRepository;
    private readonly Mock<ICategoryRepository> _mockCategoryRepository;
    private readonly Mock<ICollectionRepository> _mockCollectionRepository;
    private readonly Mock<IVisibilityService> _mockVisibilityService;
    private readonly Mock<IBulkUpdateJobs> _mockBulkUpdateJobs;
    private readonly Mock<IWorkspaceStatisticsRepository> _mockStatisticsRepository;
    private readonly Mock<ICollectionStatisticsRepository> _mockCollectionStatisticsRepository;
    private readonly ItemsController _controller;
    private const int TestWorkspaceId = 1;
    private const int TestCollectionId = 1;
    private const int TestCategoryId = 1;

    public ItemsControllerTests()
    {
        _mockItemRepository = new Mock<IItemRepository>();
        _mockCategoryRepository = new Mock<ICategoryRepository>();
        _mockCollectionRepository = new Mock<ICollectionRepository>();
        _mockVisibilityService = new Mock<IVisibilityService>();
        _mockBulkUpdateJobs = new Mock<IBulkUpdateJobs>();
        _mockStatisticsRepository = new Mock<IWorkspaceStatisticsRepository>();
        _mockCollectionStatisticsRepository = new Mock<ICollectionStatisticsRepository>();
        _mockItemRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(new Item { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId });
        _controller = new ItemsController(
            _mockItemReads.Object,
            new ItemWriteService(_mockItemRepository.Object, _mockCategoryRepository.Object,
                _mockCollectionRepository.Object, _mockVisibilityService.Object, _mockBulkUpdateJobs.Object),
            new ItemViewRecorder(_mockItemRepository.Object, _mockStatisticsRepository.Object,
                _mockCollectionStatisticsRepository.Object, TimeProvider.System));

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

    [Theory]
    [InlineData(null, false)]
    [InlineData(10, false)]
    [InlineData(10, true)]
    public async Task GetItems_ForwardsScopeAndFilter(int? categoryId, bool descendants)
    {
        Item[] items = [new() { Id = 1 }, new() { Id = 2 }];
        _mockItemReads.Setup(reads => reads.GetAllAsync(TestWorkspaceId, categoryId, descendants)).ReturnsAsync(items);
        var response = Assert.IsType<OkObjectResult>((await _controller.GetItems(categoryId, descendants)).Result);
        Assert.Equal(items, Assert.IsAssignableFrom<IEnumerable<Item>>(response.Value));
        Assert.False(_controller.Response.Headers.ContainsKey("X-Total-Count"));
    }

    [Theory]
    [InlineData(null, null, 3)]
    [InlineData(0, null, 3)]
    [InlineData(1, null, 2)]
    [InlineData(null, 0, 0)]
    [InlineData(null, 2, 2)]
    [InlineData(1, 1, 1)]
    [InlineData(10, 2, 0)]
    public async Task GetItems_PaginatesAndReturnsTotal(int? skip, int? take, int count)
    {
        Item[] items = [new() { Id = 1 }, new() { Id = 2 }, new() { Id = 3 }];
        _mockItemReads.Setup(reads => reads.GetAllAsync(TestWorkspaceId, null, false)).ReturnsAsync(items);
        var response = Assert.IsType<OkObjectResult>((await _controller.GetItems(skip: skip, take: take)).Result);
        Assert.Equal(count, Assert.IsAssignableFrom<IEnumerable<Item>>(response.Value).Count());
        if (skip.HasValue || take.HasValue) Assert.Equal("3", _controller.Response.Headers["X-Total-Count"]);
    }

    [Fact]
    public async Task GetItems_CacheValidatorDescribesThePageAndItsTotal()
    {
        var items = new List<Item> { new() { Id = 1 }, new() { Id = 2 }, new() { Id = 3 } };
        _mockItemReads.Setup(reads => reads.GetAllAsync(TestWorkspaceId, null, false)).ReturnsAsync(items);
        await _controller.GetItems(take: 1);
        var firstTag = _controller.Response.Headers.ETag.ToString();
        _controller.Request.Headers.IfNoneMatch = firstTag;
        Assert.Equal(304, Assert.IsType<StatusCodeResult>((await _controller.GetItems(take: 1)).Result).StatusCode);
        Assert.Equal("3", _controller.Response.Headers["X-Total-Count"]);
        Assert.IsType<OkObjectResult>((await _controller.GetItems(skip: 1, take: 1)).Result);
        Assert.NotEqual(firstTag, _controller.Response.Headers.ETag.ToString());
        items.Add(new Item { Id = 4 });
        Assert.IsType<OkObjectResult>((await _controller.GetItems(take: 1)).Result);
        Assert.NotEqual(firstTag, _controller.Response.Headers.ETag.ToString());
    }

    [Fact]
    public async Task GetItems_ReturnsEmptyList()
    {
        _mockItemReads.Setup(reads => reads.GetAllAsync(TestWorkspaceId, null, false)).ReturnsAsync(Array.Empty<Item>());
        var response = Assert.IsType<OkObjectResult>((await _controller.GetItems()).Result);
        Assert.Empty(Assert.IsAssignableFrom<IEnumerable<Item>>(response.Value));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task GetItem_MapsTheScopedProjection(bool exists)
    {
        var item = exists ? new Item { Id = 10, Name = "Dune" } : null;
        _mockItemReads.Setup(reads => reads.GetByIdAsync(10, TestWorkspaceId)).ReturnsAsync(item);
        var response = (await _controller.GetItem(10)).Result;
        if (exists) Assert.Same(item, Assert.IsType<OkObjectResult>(response).Value);
        else Assert.IsType<NotFoundResult>(response);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Write_RejectsActiveCollectionBulkUpdate(bool update)
    {
        _mockBulkUpdateJobs.Setup(queue => queue.GetActiveJobForCollection(TestCollectionId, TestWorkspaceId))
            .Returns(new BulkUpdateJob());
        var result = update
            ? await _controller.UpdateItem(1, new UpdateItemRequest { CollectionId = TestCollectionId })
            : await _controller.CreateItem(new CreateItemRequest { CollectionId = TestCollectionId });
        Assert.IsType<ConflictObjectResult>(result.Result);
        _mockItemRepository.Verify(repo => repo.CreateAsync(It.IsAny<Item>()), Times.Never);
        _mockItemRepository.Verify(repo => repo.UpdateAsync(It.IsAny<int>(), It.IsAny<Item>(), It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task UpdateItem_RejectsChangingCollectionBeforeAnyWrite()
    {
        var result = await _controller.UpdateItem(1, new UpdateItemRequest { CollectionId = 2, CategoryId = 20 });
        Assert.Equal("An item cannot be moved to a different collection.", Assert.IsType<BadRequestObjectResult>(result.Result).Value);
        _mockItemRepository.Verify(repo => repo.UpdateAsync(It.IsAny<int>(), It.IsAny<Item>(), It.IsAny<int>()), Times.Never);
        _mockCollectionRepository.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task UpdateItem_RejectsUnavailableOwningCollection()
    {
        Assert.IsType<BadRequestObjectResult>((await _controller.UpdateItem(1, new UpdateItemRequest { CollectionId = TestCollectionId })).Result);
        _mockItemRepository.Verify(repo => repo.UpdateAsync(It.IsAny<int>(), It.IsAny<Item>(), It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task UpdateItem_RejectsCategoryOutsideOwningCollection()
    {
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId });
        Assert.IsType<BadRequestObjectResult>((await _controller.UpdateItem(1,
            new UpdateItemRequest { CollectionId = TestCollectionId, CategoryId = 99 })).Result);
        _mockItemRepository.Verify(repo => repo.UpdateAsync(It.IsAny<int>(), It.IsAny<Item>(), It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task UpdateItem_ReturnsNotFoundIfDeletedAfterValidation()
    {
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId });
        Assert.IsType<NotFoundResult>((await _controller.UpdateItem(1, new UpdateItemRequest { CollectionId = TestCollectionId })).Result);
        _mockItemRepository.Verify(repo => repo.UpdateAsync(1, It.IsAny<Item>(), TestWorkspaceId), Times.Once);
    }

    [Fact]
    public async Task RecordView_CountsOnlyExistingWorkspaceItems()
    {
        Assert.IsType<NoContentResult>(await _controller.RecordItemView(1));
        _mockStatisticsRepository.Verify(repo => repo.IncrementAsync(TestWorkspaceId, StatisticType.DailyItemView, 1,
            It.Is<DateOnly?>(date => date != null)), Times.Once);
        _mockCollectionStatisticsRepository.Verify(repo => repo.IncrementItemViewAsync(TestCollectionId, 1), Times.Once);
        Assert.IsType<NoContentResult>(await _controller.RecordItemView(99));
        _mockStatisticsRepository.VerifyNoOtherCalls();
        _mockCollectionStatisticsRepository.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RecordView_ToleratesStatisticsFailures(bool collectionFailure)
    {
        if (collectionFailure)
            _mockCollectionStatisticsRepository.Setup(repo => repo.IncrementItemViewAsync(TestCollectionId, 1)).ThrowsAsync(new InvalidOperationException());
        else
            _mockStatisticsRepository.Setup(repo => repo.IncrementAsync(TestWorkspaceId, StatisticType.DailyItemView, 1, It.IsAny<DateOnly?>()))
                .ThrowsAsync(new InvalidOperationException());
        Assert.IsType<NoContentResult>(await _controller.RecordItemView(1));
    }

    #region CreateItem Tests

    [Fact]
    public async Task CreateItem_ReturnsCreatedAtAction_WithNewItem()
    {
        // Arrange
        var request = new CreateItemRequest
        {
            Name = "New Item",
            Summary = "Summary",
            Description = "Description",
            CategoryId = TestCategoryId,
            CollectionId = TestCollectionId
        };
        var createdItem = new Item
        {
            Id = 1,
            WorkspaceId = TestWorkspaceId,
            CollectionId = TestCollectionId,
            Name = "New Item",
            Summary = "Summary",
            Description = "Description",
            CategoryId = TestCategoryId
        };
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test Collection", Visibility = Visibility.Private };
        var category = new Category { Id = TestCategoryId, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Test Category" };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockCategoryRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { category });
        _mockItemRepository.Setup(repo => repo.CreateAsync(It.IsAny<Item>()))
            .ReturnsAsync(createdItem);

        // Act
        var result = await _controller.CreateItem(request);

        // Assert
        var createdResult = Assert.IsType<CreatedAtActionResult>(result.Result);
        Assert.Equal(nameof(_controller.GetItem), createdResult.ActionName);
        var returnedItem = Assert.IsType<Item>(createdResult.Value);
        Assert.Equal("New Item", returnedItem.Name);
    }

    #endregion

    #region UpdateItem Tests

    [Fact]
    public async Task UpdateItem_ReturnsOkResult_WhenItemExists()
    {
        // Arrange
        var request = new UpdateItemRequest
        {
            Name = "Updated Item",
            Summary = "Updated Summary",
            Description = "Updated Description",
            CategoryId = TestCategoryId,
            CollectionId = TestCollectionId
        };
        var updatedItem = new Item
        {
            Id = 1,
            WorkspaceId = TestWorkspaceId,
            CollectionId = TestCollectionId,
            Name = "Updated Item",
            Summary = "Updated Summary",
            Description = "Updated Description",
            CategoryId = TestCategoryId
        };
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test Collection", Visibility = Visibility.Private };
        var category = new Category { Id = TestCategoryId, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Test Category" };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockCategoryRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { category });
        _mockItemRepository.Setup(repo => repo.UpdateAsync(1, It.IsAny<Item>(), TestWorkspaceId))
            .ReturnsAsync(updatedItem);

        // Act
        var result = await _controller.UpdateItem(1, request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedItem = Assert.IsType<Item>(okResult.Value);
        Assert.Equal("Updated Item", returnedItem.Name);
    }

    [Fact]
    public async Task UpdateItem_ReturnsNotFound_WhenItemDoesNotExist()
    {
        // Arrange
        var request = new UpdateItemRequest
        {
            Name = "Updated Item",
            CollectionId = TestCollectionId
        };
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test Collection", Visibility = Visibility.Private };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockCategoryRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category>());
        _mockItemRepository.Setup(repo => repo.UpdateAsync(999, It.IsAny<Item>(), TestWorkspaceId))
            .ReturnsAsync((Item?)null);

        // Act
        var result = await _controller.UpdateItem(999, request);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    #endregion

    #region DeleteItem Tests

    [Fact]
    public async Task DeleteItem_ReturnsNoContent_WhenItemExists()
    {
        // Arrange
        _mockItemRepository.Setup(repo => repo.DeleteAsync(1, TestWorkspaceId))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.DeleteItem(1);

        // Assert
        Assert.IsType<NoContentResult>(result);
    }

    [Fact]
    public async Task DeleteItem_ReturnsNotFound_WhenItemDoesNotExist()
    {
        // Arrange
        _mockItemRepository.Setup(repo => repo.DeleteAsync(999, TestWorkspaceId))
            .ReturnsAsync(false);

        // Act
        var result = await _controller.DeleteItem(999);

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    #endregion

    #region UserFlag Tests

    [Fact]
    public async Task CreateItem_PersistsUserFlag_WhenProvided()
    {
        // Arrange
        var request = new CreateItemRequest
        {
            Name = "Item with Flag",
            Summary = "Summary",
            Description = "Description",
            CategoryId = TestCategoryId,
            CollectionId = TestCollectionId,
            UserFlag = UserFlag.Want
        };
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test Collection", Visibility = Visibility.Private };
        var category = new Category { Id = TestCategoryId, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Test Category" };

        Item? capturedItem = null;
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockCategoryRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { category });
        _mockItemRepository.Setup(repo => repo.CreateAsync(It.IsAny<Item>()))
            .Callback<Item>(item => capturedItem = item)
            .ReturnsAsync((Item item) => new Item
            {
                Id = 1,
                WorkspaceId = item.WorkspaceId,
                CollectionId = item.CollectionId,
                Name = item.Name,
                UserFlag = item.UserFlag
            });

        // Act
        var result = await _controller.CreateItem(request);

        // Assert
        Assert.NotNull(capturedItem);
        Assert.Equal(UserFlag.Want, capturedItem!.UserFlag);
        var createdResult = Assert.IsType<CreatedAtActionResult>(result.Result);
        var returnedItem = Assert.IsType<Item>(createdResult.Value);
        Assert.Equal(UserFlag.Want, returnedItem.UserFlag);
    }

    [Fact]
    public async Task CreateItem_DefaultsUserFlagToHave_WhenNotProvided()
    {
        // Arrange
        var request = new CreateItemRequest
        {
            Name = "Item without Flag",
            CategoryId = TestCategoryId,
            CollectionId = TestCollectionId
            // UserFlag not set - should default to Have
        };
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test Collection", Visibility = Visibility.Private };
        var category = new Category { Id = TestCategoryId, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Test Category" };

        Item? capturedItem = null;
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockCategoryRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { category });
        _mockItemRepository.Setup(repo => repo.CreateAsync(It.IsAny<Item>()))
            .Callback<Item>(item => capturedItem = item)
            .ReturnsAsync((Item item) => new Item
            {
                Id = 1,
                WorkspaceId = item.WorkspaceId,
                CollectionId = item.CollectionId,
                Name = item.Name,
                UserFlag = item.UserFlag
            });

        // Act
        var result = await _controller.CreateItem(request);

        // Assert
        Assert.NotNull(capturedItem);
        Assert.Equal(UserFlag.Have, capturedItem!.UserFlag);
    }

    [Fact]
    public async Task UpdateItem_PersistsUserFlag_WhenChanged()
    {
        // Arrange
        var request = new UpdateItemRequest
        {
            Name = "Updated Item",
            Summary = "Updated Summary",
            Description = "Updated Description",
            CategoryId = TestCategoryId,
            CollectionId = TestCollectionId,
            UserFlag = UserFlag.TradeOrSell
        };
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test Collection", Visibility = Visibility.Private };
        var category = new Category { Id = TestCategoryId, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Test Category" };

        Item? capturedItem = null;
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockCategoryRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { category });
        _mockItemRepository.Setup(repo => repo.UpdateAsync(1, It.IsAny<Item>(), TestWorkspaceId))
            .Callback<int, Item, int>((id, item, workspaceId) => capturedItem = item)
            .ReturnsAsync((int id, Item item, int workspaceId) => new Item
            {
                Id = id,
                WorkspaceId = workspaceId,
                CollectionId = item.CollectionId,
                Name = item.Name,
                UserFlag = item.UserFlag
            });

        // Act
        var result = await _controller.UpdateItem(1, request);

        // Assert
        Assert.NotNull(capturedItem);
        Assert.Equal(UserFlag.TradeOrSell, capturedItem!.UserFlag);
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var returnedItem = Assert.IsType<Item>(okResult.Value);
        Assert.Equal(UserFlag.TradeOrSell, returnedItem.UserFlag);
    }

    [Theory]
    [InlineData(UserFlag.Have)]
    [InlineData(UserFlag.Want)]
    [InlineData(UserFlag.TradeOrSell)]
    public async Task CreateItem_PersistsAllUserFlagValues(UserFlag userFlag)
    {
        // Arrange
        var request = new CreateItemRequest
        {
            Name = $"Item with {userFlag} Flag",
            CollectionId = TestCollectionId,
            UserFlag = userFlag
        };
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test Collection", Visibility = Visibility.Private };

        Item? capturedItem = null;
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockCategoryRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category>());
        _mockItemRepository.Setup(repo => repo.CreateAsync(It.IsAny<Item>()))
            .Callback<Item>(item => capturedItem = item)
            .ReturnsAsync((Item item) => new Item
            {
                Id = 1,
                WorkspaceId = item.WorkspaceId,
                CollectionId = item.CollectionId,
                Name = item.Name,
                UserFlag = item.UserFlag
            });

        // Act
        var result = await _controller.CreateItem(request);

        // Assert
        Assert.NotNull(capturedItem);
        Assert.Equal(userFlag, capturedItem!.UserFlag);
    }

    #endregion

    #region Visibility Default Tests

    [Fact]
    public async Task CreateItem_DefaultsToPrivate_WhenCategoryIsPrivate()
    {
        // Arrange
        var request = new CreateItemRequest
        {
            Name = "New Item",
            CollectionId = TestCollectionId,
            CategoryId = TestCategoryId
        };
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test Collection", Visibility = Visibility.Public };
        var category = new Category { Id = TestCategoryId, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Private Category", Visibility = Visibility.Private, EffectiveIsPublic = false };

        Item? capturedItem = null;
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockCategoryRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { category });
        _mockItemRepository.Setup(repo => repo.CreateAsync(It.IsAny<Item>()))
            .Callback<Item>(item => capturedItem = item)
            .ReturnsAsync((Item item) => new Item { Id = 1, WorkspaceId = item.WorkspaceId, Name = item.Name, Visibility = item.Visibility });

        // Act
        await _controller.CreateItem(request);

        // Assert
        Assert.NotNull(capturedItem);
        Assert.Equal(Visibility.Private, capturedItem!.Visibility);
    }

    [Fact]
    public async Task CreateItem_DefaultsToPublic_WhenCategoryIsPublic()
    {
        // Arrange
        var request = new CreateItemRequest
        {
            Name = "New Item",
            CollectionId = TestCollectionId,
            CategoryId = TestCategoryId
        };
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test Collection", Visibility = Visibility.Public };
        var category = new Category { Id = TestCategoryId, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Public Category", Visibility = Visibility.Public, EffectiveIsPublic = true };

        Item? capturedItem = null;
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockCategoryRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { category });
        _mockItemRepository.Setup(repo => repo.CreateAsync(It.IsAny<Item>()))
            .Callback<Item>(item => capturedItem = item)
            .ReturnsAsync((Item item) => new Item { Id = 1, WorkspaceId = item.WorkspaceId, Name = item.Name, Visibility = item.Visibility });

        // Act
        await _controller.CreateItem(request);

        // Assert
        Assert.NotNull(capturedItem);
        Assert.Equal(Visibility.Public, capturedItem!.Visibility);
    }

    [Fact]
    public async Task CreateItem_DefaultsToCollectionVisibility_WhenNoCategory()
    {
        // Arrange
        var request = new CreateItemRequest
        {
            Name = "New Item",
            CollectionId = TestCollectionId
            // No CategoryId
        };
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Public Collection", Visibility = Visibility.Public };

        Item? capturedItem = null;
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockCategoryRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category>());
        _mockItemRepository.Setup(repo => repo.CreateAsync(It.IsAny<Item>()))
            .Callback<Item>(item => capturedItem = item)
            .ReturnsAsync((Item item) => new Item { Id = 1, WorkspaceId = item.WorkspaceId, Name = item.Name, Visibility = item.Visibility });

        // Act
        await _controller.CreateItem(request);

        // Assert
        Assert.NotNull(capturedItem);
        Assert.Equal(Visibility.Public, capturedItem!.Visibility);
    }

    [Fact]
    public async Task UpdateItem_PreservesExistingVisibility()
    {
        // Arrange
        var request = new UpdateItemRequest
        {
            Name = "Updated Item",
            CollectionId = TestCollectionId,
            CategoryId = TestCategoryId
        };
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test Collection", Visibility = Visibility.Private };
        var category = new Category { Id = TestCategoryId, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Test Category" };
        var existingItem = new Item { Id = 1, WorkspaceId = TestWorkspaceId, CollectionId = TestCollectionId, Name = "Original", Visibility = Visibility.Public };

        Item? capturedItem = null;
        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockCategoryRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category> { category });
        _mockItemRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync(existingItem);
        _mockItemRepository.Setup(repo => repo.UpdateAsync(1, It.IsAny<Item>(), TestWorkspaceId))
            .Callback<int, Item, int>((id, item, ws) => capturedItem = item)
            .ReturnsAsync((int id, Item item, int ws) => new Item { Id = id, WorkspaceId = ws, Name = item.Name, Visibility = item.Visibility });

        // Act
        await _controller.UpdateItem(1, request);

        // Assert - Visibility should be preserved from existing item (Public), not defaulted
        Assert.NotNull(capturedItem);
        Assert.Equal(Visibility.Public, capturedItem!.Visibility);
    }

    [Fact]
    public async Task UpdateItem_DoesNotWrite_WhenExistingItemNotFound()
    {
        // Missing items cannot be recreated by an update.
        var request = new UpdateItemRequest
        {
            Name = "Updated Item",
            CollectionId = TestCollectionId
        };
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test Collection", Visibility = Visibility.Private };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockCategoryRepository.Setup(repo => repo.GetByCollectionAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(new List<Category>());
        _mockItemRepository.Setup(repo => repo.GetByIdAsync(1, TestWorkspaceId))
            .ReturnsAsync((Item?)null);
        _mockItemRepository.Setup(repo => repo.UpdateAsync(1, It.IsAny<Item>(), TestWorkspaceId))
            .ReturnsAsync((Item?)null);

        // Act
        var result = await _controller.UpdateItem(1, request);

        // Assert
        Assert.IsType<NotFoundResult>(result.Result);
    }

    #endregion

    #region Security Tests

    [Fact]
    public async Task CreateItem_ReturnsBadRequest_WhenCollectionNotOwnedByWorkspace()
    {
        // Arrange - Collection returns null (not found for workspace)
        var request = new CreateItemRequest
        {
            Name = "New Item",
            CollectionId = 999  // Collection that doesn't belong to workspace
        };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(999, TestWorkspaceId))
            .ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.CreateItem(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    [Fact]
    public async Task CreateItem_ReturnsBadRequest_WhenCategoryNotOwnedByWorkspace()
    {
        // Arrange - Collection is valid but Category is not
        var request = new CreateItemRequest
        {
            Name = "New Item",
            CollectionId = TestCollectionId,
            CategoryId = 999  // Category that doesn't belong to workspace
        };
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test Collection" };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockCategoryRepository.Setup(repo => repo.GetByIdAsync(999, TestWorkspaceId))
            .ReturnsAsync((Category?)null);

        // Act
        var result = await _controller.CreateItem(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    [Fact]
    public async Task CreateItem_ReturnsBadRequest_WhenCategoryBelongsToDifferentCollection()
    {
        // Arrange - Category exists but belongs to different collection
        var request = new CreateItemRequest
        {
            Name = "New Item",
            CollectionId = TestCollectionId,
            CategoryId = TestCategoryId
        };
        var collection = new Collection { Id = TestCollectionId, WorkspaceId = TestWorkspaceId, Name = "Test Collection" };
        var category = new Category { Id = TestCategoryId, WorkspaceId = TestWorkspaceId, CollectionId = 999, Name = "Test Category" }; // Different CollectionId

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(TestCollectionId, TestWorkspaceId))
            .ReturnsAsync(collection);
        _mockCategoryRepository.Setup(repo => repo.GetByIdAsync(TestCategoryId, TestWorkspaceId))
            .ReturnsAsync(category);

        // Act
        var result = await _controller.CreateItem(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    [Fact]
    public async Task UpdateItem_ReturnsBadRequest_WhenCollectionNotOwnedByWorkspace()
    {
        // Arrange
        var request = new UpdateItemRequest
        {
            Name = "Updated Item",
            CollectionId = 999  // Collection that doesn't belong to workspace
        };

        _mockCollectionRepository.Setup(repo => repo.GetByIdAsync(999, TestWorkspaceId))
            .ReturnsAsync((Collection?)null);

        // Act
        var result = await _controller.UpdateItem(1, request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    #endregion
}
