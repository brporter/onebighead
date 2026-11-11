using Moq;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using OneBigHead.Server.Services.BulkUpdate;
using OneBigHead.Server.Services.Items;

namespace OneBigHead.Server.Tests.Unit.Services;

public class ItemWriteServiceTests
{
    private const int WorkspaceId = 7;
    private const int CollectionId = 3;
    private readonly Mock<IItemRepository> _items = new();
    private readonly Mock<ICategoryRepository> _categories = new();
    private readonly Mock<ICollectionRepository> _collections = new();
    private readonly Mock<IBulkUpdateJobs> _jobs = new();
    private ItemWriteService Service => new(_items.Object, _categories.Object, _collections.Object, new VisibilityService(), _jobs.Object);

    [Theory]
    [InlineData(null, false, true, false)]
    [InlineData(null, true, false, true)]
    [InlineData(4, true, true, true)]
    [InlineData(4, true, false, false)]
    [InlineData(4, false, true, false)]
    public async Task Create_UsesScopedParentVisibilityAndPreservesTheDraft(int? categoryId, bool publicCollection, bool publicCategory, bool expectedPublic)
    {
        SetParent(publicCollection, publicCategory);
        _items.Setup(repository => repository.CreateAsync(It.IsAny<Item>())).ReturnsAsync((Item item) => { item.Id = 20; return item; });
        var request = new CreateItemRequest { CollectionId = CollectionId, CategoryId = categoryId, Name = "Draft",
            Summary = "Summary", Description = "Description", UserFlag = UserFlag.Want,
            Properties = [new("General", "Year", "2026")] };

        var result = await Service.CreateAsync(WorkspaceId, request);

        Assert.Equal(ItemWriteStatus.Success, result.Status);
        var item = Assert.IsType<Item>(result.Item);
        Assert.Equal(20, item.Id);
        Assert.Equal(WorkspaceId, item.WorkspaceId);
        Assert.Equal(CollectionId, item.CollectionId);
        Assert.Equal(categoryId, item.CategoryId);
        Assert.Equal(request.Name, item.Name);
        Assert.Equal(request.Summary, item.Summary);
        Assert.Equal(request.Description, item.Description);
        Assert.Equal(request.UserFlag, item.UserFlag);
        Assert.Equal(request.Properties, item.Properties);
        Assert.Equal(expectedPublic ? Visibility.Public : Visibility.Private, item.Visibility);
        Assert.Equal(expectedPublic, item.EffectiveIsPublic);
        _categories.Verify(repository => repository.GetByCollectionAsync(CollectionId, WorkspaceId), Times.Once);
        _collections.Verify(repository => repository.GetByIdAsync(CollectionId, WorkspaceId), Times.Once);
        _jobs.Verify(jobs => jobs.GetActiveJobForCollection(CollectionId, WorkspaceId), Times.Once);
    }

    [Fact]
    public async Task Update_PreservesPublicationAndReturnsThePersistedRecord()
    {
        SetParent(publicCollection: true, publicCategory: true);
        _items.Setup(repository => repository.GetByIdAsync(20, WorkspaceId)).ReturnsAsync(
            new Item { Id = 20, WorkspaceId = WorkspaceId, CollectionId = CollectionId, Visibility = Visibility.Private });
        var stored = new Item { Id = 20, WorkspaceId = WorkspaceId, CollectionId = CollectionId, CategoryId = 4,
            Name = "Persisted", Visibility = Visibility.Public };
        _items.Setup(repository => repository.UpdateAsync(20, It.IsAny<Item>(), WorkspaceId))
            .Callback<int, Item, int>((_, item, _) => Assert.Equal(Visibility.Private, item.Visibility))
            .ReturnsAsync(stored);

        var result = await Service.UpdateAsync(WorkspaceId, 20, new UpdateItemRequest { Name = "Draft", CollectionId = CollectionId, CategoryId = 4 });

        Assert.Equal(ItemWriteStatus.Success, result.Status);
        Assert.Same(stored, result.Item);
        Assert.True(stored.EffectiveIsPublic);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Write_PropagatesPersistenceFailureWithoutRetry(bool update)
    {
        SetParent(publicCollection: true, publicCategory: true);
        _items.Setup(repository => repository.GetByIdAsync(20, WorkspaceId)).ReturnsAsync(new Item { Id = 20, CollectionId = CollectionId });
        var failure = new InvalidOperationException("Persistence failed");
        _items.Setup(repository => repository.CreateAsync(It.IsAny<Item>())).ThrowsAsync(failure);
        _items.Setup(repository => repository.UpdateAsync(20, It.IsAny<Item>(), WorkspaceId)).ThrowsAsync(failure);

        var caught = await Assert.ThrowsAsync<InvalidOperationException>(() => update
            ? Service.UpdateAsync(WorkspaceId, 20, new UpdateItemRequest { CollectionId = CollectionId })
            : Service.CreateAsync(WorkspaceId, new CreateItemRequest { CollectionId = CollectionId }));

        Assert.Same(failure, caught);
        _items.Verify(repository => repository.CreateAsync(It.IsAny<Item>()), update ? Times.Never() : Times.Once());
        _items.Verify(repository => repository.UpdateAsync(20, It.IsAny<Item>(), WorkspaceId), update ? Times.Once() : Times.Never());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Delete_ForwardsWorkspaceScopeAndReportsWhetherAnItemWasRemoved(bool deleted)
    {
        _items.Setup(repository => repository.DeleteAsync(20, WorkspaceId)).ReturnsAsync(deleted);
        Assert.Equal(deleted, await Service.DeleteAsync(WorkspaceId, 20));
        _items.Verify(repository => repository.DeleteAsync(20, WorkspaceId), Times.Once);
        _collections.VerifyNoOtherCalls();
        _categories.VerifyNoOtherCalls();
    }

    private void SetParent(bool publicCollection, bool publicCategory)
    {
        _collections.Setup(repository => repository.GetByIdAsync(CollectionId, WorkspaceId)).ReturnsAsync(
            new Collection { Id = CollectionId, WorkspaceId = WorkspaceId, Visibility = publicCollection ? Visibility.Public : Visibility.Private });
        _categories.Setup(repository => repository.GetByCollectionAsync(CollectionId, WorkspaceId)).ReturnsAsync(
            [new Category { Id = 4, WorkspaceId = WorkspaceId, CollectionId = CollectionId,
                Visibility = publicCategory ? Visibility.Public : Visibility.Private }]);
    }
}
