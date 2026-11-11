using Moq;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using OneBigHead.Server.Services.Items;

namespace OneBigHead.Server.Tests.Unit.Services;

[Trait("Category", "Unit")]
public class ItemReadServiceTests
{
    private readonly Mock<IItemRepository> _items = new();
    private readonly Mock<ICategoryRepository> _categories = new();
    private readonly Mock<ICollectionRepository> _collections = new();
    private ItemReadService Service => new(_items.Object, _categories.Object, _collections.Object, new VisibilityService());

    [Fact]
    public async Task List_OrdersItemsAndProjectsEachActualCollectionWithBoundedReads()
    {
        var publicCollection = new Collection { Id = 20, WorkspaceId = 1, Visibility = Visibility.Public };
        var privateCollection = new Collection { Id = 10, WorkspaceId = 1 };
        Category[] categories = [Category(1, 20), Category(2, 20, 1), Category(3, 10)];
        Item[] items = [Item(4, 99), Item(3, 20, 2), Item(2, 10, 3), Item(1, 20)];
        items[0].EffectiveIsPublic = true;
        _items.Setup(repo => repo.GetAllAsync(1)).ReturnsAsync(items);
        _categories.Setup(repo => repo.GetAllAsync(1)).ReturnsAsync(categories);
        _collections.Setup(repo => repo.GetAllAsync(1)).ReturnsAsync([privateCollection, publicCollection]);

        var result = await Service.GetAllAsync(1);

        Assert.Equal(new int?[] { 1, 2, 3, 4 }, result.Select(item => item.Id));
        Assert.Equal(new[] { true, false, true, false }, result.Select(item => item.EffectiveIsPublic));
        _categories.Verify(repo => repo.GetAllAsync(1), Times.Once);
        _collections.Verify(repo => repo.GetAllAsync(1), Times.Once);
        _collections.Verify(repo => repo.GetByIdAsync(It.IsAny<int>(), It.IsAny<int>()), Times.Never);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CategoryFilter_BoundsTraversalAndItemsToTheRootsCollection(bool descendants)
    {
        Category[] categories = [Category(1, 20, 2), Category(2, 20, 1), Category(3, 20, 2), Category(4, 30, 1), Category(5, 30, 4)];
        var items = new[] { Item(1, 20, 1), Item(2, 20, 2), Item(3, 20, 3), Item(4, 30, 1) };
        _categories.Setup(repo => repo.GetAllAsync(1)).ReturnsAsync(categories);
        _collections.Setup(repo => repo.GetAllAsync(1)).ReturnsAsync([new Collection { Id = 20, WorkspaceId = 1, Visibility = Visibility.Public }]);
        _items.Setup(repo => repo.GetByCategoryIdsAsync(It.IsAny<IEnumerable<int>>(), 1))
            .ReturnsAsync((IEnumerable<int> ids, int _) => items.Where(item => ids.Contains(item.CategoryId!.Value)));

        var result = await Service.GetAllAsync(1, 1, descendants);

        Assert.Equal(descendants ? new int?[] { 1, 2, 3 } : [1], result.Select(item => item.Id));
        Assert.All(result, item => Assert.False(item.EffectiveIsPublic)); // Cyclic ancestry fails closed.
        _items.Verify(repo => repo.GetByCategoryIdsAsync(
            It.Is<IEnumerable<int>>(ids => ids.Count() == (descendants ? 3 : 1) && !ids.Contains(4)), 1), Times.Once);
    }

    [Fact]
    public async Task CategoryFilter_HandlesVeryDeepTreesWithoutRecursion()
    {
        var categories = Enumerable.Range(1, 20000).Select(id => Category(id, 20, id == 1 ? null : id - 1)).ToArray();
        _categories.Setup(repo => repo.GetAllAsync(1)).ReturnsAsync(categories);
        _collections.Setup(repo => repo.GetAllAsync(1)).ReturnsAsync([new Collection { Id = 20, WorkspaceId = 1, Visibility = Visibility.Public }]);
        _items.Setup(repo => repo.GetByCategoryIdsAsync(It.IsAny<IEnumerable<int>>(), 1)).ReturnsAsync([Item(1, 20, 20000)]);

        Assert.True(Assert.Single(await Service.GetAllAsync(1, 1, true)).EffectiveIsPublic);
        _items.Verify(repo => repo.GetByCategoryIdsAsync(It.Is<IEnumerable<int>>(ids => ids.Count() == 20000), 1), Times.Once);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MissingOrForeignCategory_ReturnsEmptyWithoutReadingItems(bool descendants)
    {
        _categories.Setup(repo => repo.GetAllAsync(1)).ReturnsAsync([Category(1, 20)]);
        Assert.Empty(await Service.GetAllAsync(1, 99, descendants));
        _items.VerifyNoOtherCalls();
        _collections.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(null, true)]
    [InlineData(1, true)]
    [InlineData(2, false)]
    [InlineData(99, false)]
    public async Task Detail_ProjectsTheOwningCollectionAndCategory(int? categoryId, bool expected)
    {
        var item = Item(10, 20, categoryId);
        _items.Setup(repo => repo.GetByIdAsync(10, 1)).ReturnsAsync(item);
        _collections.Setup(repo => repo.GetByIdAsync(20, 1)).ReturnsAsync(new Collection { Id = 20, WorkspaceId = 1, Visibility = Visibility.Public });
        var privateCategory = Category(2, 20);
        privateCategory.Visibility = Visibility.Private;
        _categories.Setup(repo => repo.GetByCollectionAsync(20, 1)).ReturnsAsync([Category(1, 20), privateCategory]);

        var result = await Service.GetByIdAsync(10, 1);

        Assert.Same(item, result);
        Assert.Equal(expected, result!.EffectiveIsPublic);
    }

    [Fact]
    public async Task Detail_MissingCollectionClearsStaleVisibility()
    {
        var item = Item(10, 20);
        item.EffectiveIsPublic = true;
        _items.Setup(repo => repo.GetByIdAsync(10, 1)).ReturnsAsync(item);
        Assert.False((await Service.GetByIdAsync(10, 1))!.EffectiveIsPublic);
    }

    [Fact]
    public async Task Detail_MissingOrForeignItemReturnsNull()
    {
        Assert.Null(await Service.GetByIdAsync(10, 1));
        _collections.VerifyNoOtherCalls();
        _categories.VerifyNoOtherCalls();
    }

    private static Category Category(int id, int collectionId, int? parent = null) => new()
    {
        Id = id, WorkspaceId = 1, CollectionId = collectionId, ParentCategoryId = parent, Visibility = Visibility.Public
    };

    private static Item Item(int id, int collectionId, int? categoryId = null) => new()
    {
        Id = id, WorkspaceId = 1, CollectionId = collectionId, CategoryId = categoryId, Visibility = Visibility.Public
    };
}
