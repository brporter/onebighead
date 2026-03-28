# Centralized Publish Manager Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace scattered per-entity publish/unpublish endpoints with a centralized two-endpoint API (preflight + execute) and a unified PublishResolver UI component.

**Architecture:** Backend: new `PublishManagerController` with two endpoints, new `PublishManagerService` absorbing all visibility logic. Frontend: new `PublishContext` + `PublishResolver` component rendered once at app level; all consuming components call `requestPublish`/`requestUnpublish` instead of managing their own publish flows.

**Tech Stack:** .NET 10, xUnit, Moq, React 19, Vitest, React Testing Library

---

### Task 1: Backend DTOs

Create the request/response types for the new preflight and execute endpoints.

**Files:**
- Create: `backend/src/backend/DTOs/PublishManagerRequests.cs`

- [ ] **Step 1: Write the DTO file**

Create `backend/src/backend/DTOs/PublishManagerRequests.cs`:

```csharp
using System.Text.Json.Serialization;

namespace backend.DTOs;

// === Shared Types ===

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum PublishAction
{
    Publish,
    Unpublish,
}

public class EntityRef
{
    public required string Type { get; set; } // "item", "category", "collection"
    public int Id { get; set; }
}

public class ChangedEntityInfo
{
    public required string Type { get; set; }
    public int Id { get; set; }
    public required string Name { get; set; }
}

// === Preflight ===

public class PreflightRequest
{
    public PublishAction Action { get; set; }
    public required List<EntityRef> Entities { get; set; }
}

public class PreflightResponse
{
    public bool Ready { get; set; }
    public List<PublishRequirement> Requirements { get; set; } = new();
}

[JsonPolymorphic(TypeDiscriminatorPropertyName = "kind")]
[JsonDerivedType(typeof(WorkspaceSlugRequiredRequirement), "workspace-slug-required")]
[JsonDerivedType(typeof(CollectionNotPublicRequirement), "collection-not-public")]
[JsonDerivedType(typeof(CategoryNotPublicRequirement), "category-not-public")]
[JsonDerivedType(typeof(UnpublishWillHideChildrenRequirement), "unpublish-will-hide-children")]
public abstract class PublishRequirement
{
    public abstract string Kind { get; }
}

public class WorkspaceSlugRequiredRequirement : PublishRequirement
{
    public override string Kind => "workspace-slug-required";
    public int WorkspaceId { get; set; }
    public required string WorkspaceName { get; set; }
}

public class CollectionNotPublicRequirement : PublishRequirement
{
    public override string Kind => "collection-not-public";
    public int CollectionId { get; set; }
    public required string CollectionName { get; set; }
}

public class CategoryNotPublicRequirement : PublishRequirement
{
    public override string Kind => "category-not-public";
    public int CategoryId { get; set; }
    public required string CategoryName { get; set; }
}

public class UnpublishWillHideChildrenRequirement : PublishRequirement
{
    public override string Kind => "unpublish-will-hide-children";
    public required string EntityType { get; set; }
    public int EntityId { get; set; }
    public required string EntityName { get; set; }
    public int AffectedPublicItems { get; set; }
    public int AffectedPublicCategories { get; set; }
}

// === Execute ===

public class ExecuteRequest
{
    public PublishAction Action { get; set; }
    public required List<EntityRef> Entities { get; set; }
    public List<PublishResolution> Resolutions { get; set; } = new();
}

[JsonPolymorphic(TypeDiscriminatorPropertyName = "kind")]
[JsonDerivedType(typeof(WorkspaceSlugResolution), "workspace-slug-required")]
[JsonDerivedType(typeof(CollectionNotPublicResolution), "collection-not-public")]
[JsonDerivedType(typeof(CategoryNotPublicResolution), "category-not-public")]
[JsonDerivedType(typeof(UnpublishWillHideChildrenResolution), "unpublish-will-hide-children")]
public abstract class PublishResolution
{
    public abstract string Kind { get; }
}

public class WorkspaceSlugResolution : PublishResolution
{
    public override string Kind => "workspace-slug-required";
    public required string Slug { get; set; }
}

public class CollectionNotPublicResolution : PublishResolution
{
    public override string Kind => "collection-not-public";
    public int CollectionId { get; set; }
}

public class CategoryNotPublicResolution : PublishResolution
{
    public override string Kind => "category-not-public";
    public int CategoryId { get; set; }
}

public class UnpublishWillHideChildrenResolution : PublishResolution
{
    public override string Kind => "unpublish-will-hide-children";
    public required string EntityType { get; set; }
    public int EntityId { get; set; }
}

public class ExecuteResponse
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public List<ChangedEntityInfo> Changed { get; set; } = new();
    public List<ChangedEntityInfo> Promoted { get; set; } = new();
    public string? WorkspaceSlugSet { get; set; }
    public List<PublishRequirement>? Requirements { get; set; }
}
```

- [ ] **Step 2: Verify the project builds**

Run: `dotnet build backend/src/backend`
Expected: Build succeeded

- [ ] **Step 3: Commit**

```bash
git add backend/src/backend/DTOs/PublishManagerRequests.cs
git commit -m "feat: add PublishManager DTOs for preflight/execute endpoints"
```

---

### Task 2: Backend IPublishManagerService Interface

Create the new service interface that replaces `IVisibilityService`.

**Files:**
- Create: `backend/src/backend/Services/IPublishManagerService.cs`

- [ ] **Step 1: Write the interface**

Create `backend/src/backend/Services/IPublishManagerService.cs`:

```csharp
using backend.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Services;

[GenerateTracingProxy]
public interface IPublishManagerService
{
    // Preflight and Execute
    Task<PreflightResponse> PreflightAsync(int workspaceId, PreflightRequest request);
    Task<ExecuteResponse> ExecuteAsync(int workspaceId, ExecuteRequest request);

    // Effective visibility computation (migrated from IVisibilityService)
    void ComputeEffectiveVisibility(Category category, Collection collection, IEnumerable<Category> allCategories);
    void ComputeEffectiveVisibility(Item item, Collection collection, Category? category);
    void ComputeEffectiveVisibility(IEnumerable<Category> categories, Collection collection);
    void ComputeEffectiveVisibility(IEnumerable<Item> items, Collection collection, IEnumerable<Category> categories);
}
```

- [ ] **Step 2: Verify the project builds**

Run: `dotnet build backend/src/backend`
Expected: Build succeeded

- [ ] **Step 3: Commit**

```bash
git add backend/src/backend/Services/IPublishManagerService.cs
git commit -m "feat: add IPublishManagerService interface"
```

---

### Task 3: Backend PublishManagerService — Visibility Computation

Create the service implementation with effective visibility computation (migrated from VisibilityService). Tests first.

**Files:**
- Create: `backend/tests/backend.tests/Services/PublishManagerServiceTests.cs`
- Create: `backend/src/backend/Services/PublishManagerService.cs`

- [ ] **Step 1: Write failing tests for effective visibility computation**

Create `backend/tests/backend.tests/Services/PublishManagerServiceTests.cs`:

```csharp
using backend.DTOs;
using Moq;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;

namespace backend.tests.Services;

[Trait("Category", "Unit")]
public class PublishManagerServiceTests
{
    private readonly Mock<IItemRepository> _mockItemRepository = new();
    private readonly Mock<ICategoryRepository> _mockCategoryRepository = new();
    private readonly Mock<ICollectionRepository> _mockCollectionRepository = new();
    private readonly Mock<IWorkspaceRepository> _mockWorkspaceRepository = new();
    private readonly PublishManagerService _service;

    public PublishManagerServiceTests()
    {
        _service = new PublishManagerService(
            _mockItemRepository.Object,
            _mockCategoryRepository.Object,
            _mockCollectionRepository.Object,
            _mockWorkspaceRepository.Object);
    }

    #region ComputeEffectiveVisibility — Category

    [Fact]
    public void ComputeEffectiveVisibility_Category_PublicCollectionPublicCategory_IsPublic()
    {
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var category = new Category { Id = 1, Name = "Cat", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public };

        _service.ComputeEffectiveVisibility(category, collection, new List<Category> { category });

        Assert.True(category.EffectiveIsPublic);
    }

    [Fact]
    public void ComputeEffectiveVisibility_Category_PrivateCollection_IsNotPublic()
    {
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Private };
        var category = new Category { Id = 1, Name = "Cat", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public };

        _service.ComputeEffectiveVisibility(category, collection, new List<Category> { category });

        Assert.False(category.EffectiveIsPublic);
    }

    [Fact]
    public void ComputeEffectiveVisibility_Category_PrivateParent_IsNotPublic()
    {
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var parent = new Category { Id = 1, Name = "Parent", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Private };
        var child = new Category { Id = 2, Name = "Child", WorkspaceId = 1, CollectionId = 1, ParentCategoryId = 1, Visibility = Visibility.Public };
        var all = new List<Category> { parent, child };

        _service.ComputeEffectiveVisibility(all, collection);

        Assert.False(parent.EffectiveIsPublic);
        Assert.False(child.EffectiveIsPublic);
    }

    [Fact]
    public void ComputeEffectiveVisibility_Category_PublicParent_IsPublic()
    {
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var parent = new Category { Id = 1, Name = "Parent", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public };
        var child = new Category { Id = 2, Name = "Child", WorkspaceId = 1, CollectionId = 1, ParentCategoryId = 1, Visibility = Visibility.Public };
        var all = new List<Category> { parent, child };

        _service.ComputeEffectiveVisibility(all, collection);

        Assert.True(parent.EffectiveIsPublic);
        Assert.True(child.EffectiveIsPublic);
    }

    #endregion

    #region ComputeEffectiveVisibility — Item

    [Fact]
    public void ComputeEffectiveVisibility_Item_AllPublic_IsPublic()
    {
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var category = new Category { Id = 1, Name = "Cat", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public, EffectiveIsPublic = true };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, CategoryId = 1, Visibility = Visibility.Public };

        _service.ComputeEffectiveVisibility(item, collection, category);

        Assert.True(item.EffectiveIsPublic);
    }

    [Fact]
    public void ComputeEffectiveVisibility_Item_PrivateCategory_IsNotPublic()
    {
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var category = new Category { Id = 1, Name = "Cat", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Private, EffectiveIsPublic = false };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, CategoryId = 1, Visibility = Visibility.Public };

        _service.ComputeEffectiveVisibility(item, collection, category);

        Assert.False(item.EffectiveIsPublic);
    }

    [Fact]
    public void ComputeEffectiveVisibility_Item_NullCategory_UsesCollectionOnly()
    {
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public };

        _service.ComputeEffectiveVisibility(item, collection, null);

        Assert.True(item.EffectiveIsPublic);
    }

    #endregion
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test backend/tests/backend.tests --filter "FullyQualifiedName~PublishManagerServiceTests"`
Expected: FAIL — `PublishManagerService` does not exist

- [ ] **Step 3: Write the PublishManagerService with visibility computation**

Create `backend/src/backend/Services/PublishManagerService.cs`:

```csharp
using backend.DTOs;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services;

public class PublishManagerService : IPublishManagerService
{
    private readonly IItemRepository _itemRepository;
    private readonly ICategoryRepository _categoryRepository;
    private readonly ICollectionRepository _collectionRepository;
    private readonly IWorkspaceRepository _workspaceRepository;

    public PublishManagerService(
        IItemRepository itemRepository,
        ICategoryRepository categoryRepository,
        ICollectionRepository collectionRepository,
        IWorkspaceRepository workspaceRepository)
    {
        _itemRepository = itemRepository;
        _categoryRepository = categoryRepository;
        _collectionRepository = collectionRepository;
        _workspaceRepository = workspaceRepository;
    }

    // Preflight and Execute are implemented in subsequent tasks
    public Task<PreflightResponse> PreflightAsync(int workspaceId, PreflightRequest request)
    {
        throw new NotImplementedException();
    }

    public Task<ExecuteResponse> ExecuteAsync(int workspaceId, ExecuteRequest request)
    {
        throw new NotImplementedException();
    }

    #region Effective Visibility Computation

    public void ComputeEffectiveVisibility(Category category, Collection collection, IEnumerable<Category> allCategories)
    {
        var categoryLookup = allCategories as IDictionary<int, Category>
            ?? (allCategories as IList<Category> ?? allCategories.ToList()).ToDictionary(c => c.Id);
        ComputeEffectiveVisibilityInternal(category, collection, categoryLookup);
    }

    public void ComputeEffectiveVisibility(Item item, Collection collection, Category? category)
    {
        if (!collection.EffectiveIsPublic)
        {
            item.EffectiveIsPublic = false;
            return;
        }

        if (category != null && !category.EffectiveIsPublic)
        {
            item.EffectiveIsPublic = false;
            return;
        }

        item.EffectiveIsPublic = item.Visibility == Visibility.Public;
    }

    public void ComputeEffectiveVisibility(IEnumerable<Category> categories, Collection collection)
    {
        var categoryList = categories.ToList();
        var categoryLookup = categoryList.ToDictionary(c => c.Id);

        var processed = new HashSet<int>();
        var ordered = new List<Category>();

        void ProcessCategory(Category cat)
        {
            if (processed.Contains(cat.Id)) return;

            if (cat.ParentCategoryId.HasValue && categoryLookup.TryGetValue(cat.ParentCategoryId.Value, out var parent))
            {
                if (!processed.Contains(parent.Id))
                {
                    ProcessCategory(parent);
                }
            }

            processed.Add(cat.Id);
            ordered.Add(cat);
        }

        foreach (var category in categoryList)
        {
            ProcessCategory(category);
        }

        foreach (var category in ordered)
        {
            ComputeEffectiveVisibilityInternal(category, collection, categoryLookup);
        }
    }

    public void ComputeEffectiveVisibility(IEnumerable<Item> items, Collection collection, IEnumerable<Category> categories)
    {
        var categoryLookup = categories.ToDictionary(c => c.Id);

        foreach (var item in items)
        {
            var category = item.CategoryId.HasValue && categoryLookup.TryGetValue(item.CategoryId.Value, out var cat)
                ? cat
                : null;
            ComputeEffectiveVisibility(item, collection, category);
        }
    }

    private static void ComputeEffectiveVisibilityInternal(Category category, Collection collection, IDictionary<int, Category> categoryLookup)
    {
        if (!collection.EffectiveIsPublic)
        {
            category.EffectiveIsPublic = false;
            return;
        }

        if (category.ParentCategoryId.HasValue)
        {
            if (categoryLookup.TryGetValue(category.ParentCategoryId.Value, out var parentCategory) && !parentCategory.EffectiveIsPublic)
            {
                category.EffectiveIsPublic = false;
                return;
            }
        }

        category.EffectiveIsPublic = category.Visibility == Visibility.Public;
    }

    #endregion

    #region Internal Helpers

    private static void CollectDescendantCategoryIds(int parentId, IList<Category> allCategories, HashSet<int> result)
    {
        foreach (var cat in allCategories)
        {
            if (cat.ParentCategoryId == parentId && !result.Contains(cat.Id))
            {
                result.Add(cat.Id);
                CollectDescendantCategoryIds(cat.Id, allCategories, result);
            }
        }
    }

    private static void PromoteParentCategories(Category category, IDictionary<int, Category> categoryLookup, List<ChangedEntityInfo> promoted)
    {
        if (!category.ParentCategoryId.HasValue) return;
        if (!categoryLookup.TryGetValue(category.ParentCategoryId.Value, out var parent)) return;

        PromoteParentCategories(parent, categoryLookup, promoted);

        if (parent.Visibility == Visibility.Private)
        {
            parent.Visibility = Visibility.Public;
            promoted.Add(new ChangedEntityInfo { Type = "category", Id = parent.Id, Name = parent.Name });
        }
    }

    #endregion
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test backend/tests/backend.tests --filter "FullyQualifiedName~PublishManagerServiceTests"`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add backend/src/backend/Services/PublishManagerService.cs backend/tests/backend.tests/Services/PublishManagerServiceTests.cs
git commit -m "feat: add PublishManagerService with visibility computation"
```

---

### Task 4: Backend PublishManagerService — Preflight Logic

Add preflight analysis to the service. This loads entities and their ancestor chains, identifies blockers (publish) or impact warnings (unpublish), and deduplicates across multiple entities.

**Files:**
- Modify: `backend/tests/backend.tests/Services/PublishManagerServiceTests.cs`
- Modify: `backend/src/backend/Services/PublishManagerService.cs`

- [ ] **Step 1: Write failing tests for publish preflight**

Add to `backend/tests/backend.tests/Services/PublishManagerServiceTests.cs` after the existing `#endregion`:

```csharp
    #region Preflight — Publish

    [Fact]
    public async Task Preflight_Publish_AllAncestorsPublicAndSlugSet_ReturnsReady()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = "my-ws" };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var category = new Category { Id = 1, Name = "Cat", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, CategoryId = 1, Visibility = Visibility.Private };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockItemRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(item);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(category);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, 1)).ReturnsAsync(new List<Category> { category });

        var result = await _service.PreflightAsync(1, new PreflightRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } }
        });

        Assert.True(result.Ready);
        Assert.Empty(result.Requirements);
    }

    [Fact]
    public async Task Preflight_Publish_Item_PrivateCategoryAndCollection_ReturnsBothRequirements()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = "my-ws" };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Private };
        var category = new Category { Id = 1, Name = "Cat", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Private };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, CategoryId = 1, Visibility = Visibility.Private };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockItemRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(item);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(category);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, 1)).ReturnsAsync(new List<Category> { category });

        var result = await _service.PreflightAsync(1, new PreflightRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } }
        });

        Assert.False(result.Ready);
        Assert.Equal(2, result.Requirements.Count);
        Assert.Contains(result.Requirements, r => r is CollectionNotPublicRequirement c && c.CollectionId == 1);
        Assert.Contains(result.Requirements, r => r is CategoryNotPublicRequirement c && c.CategoryId == 1);
    }

    [Fact]
    public async Task Preflight_Publish_NoSlug_ReturnsSlugRequirement()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = null };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Private };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockItemRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(item);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);

        var result = await _service.PreflightAsync(1, new PreflightRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } }
        });

        Assert.False(result.Ready);
        Assert.Single(result.Requirements);
        Assert.IsType<WorkspaceSlugRequiredRequirement>(result.Requirements[0]);
    }

    [Fact]
    public async Task Preflight_Publish_DeduplicatesAcrossMultipleItems()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = "my-ws" };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Private };
        var category = new Category { Id = 1, Name = "Cat", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Private };
        var item1 = new Item { Id = 1, Name = "Item1", WorkspaceId = 1, CollectionId = 1, CategoryId = 1, Visibility = Visibility.Private };
        var item2 = new Item { Id = 2, Name = "Item2", WorkspaceId = 1, CollectionId = 1, CategoryId = 1, Visibility = Visibility.Private };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockItemRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(item1);
        _mockItemRepository.Setup(r => r.GetByIdAsync(2, 1)).ReturnsAsync(item2);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(category);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, 1)).ReturnsAsync(new List<Category> { category });

        var result = await _service.PreflightAsync(1, new PreflightRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef>
            {
                new() { Type = "item", Id = 1 },
                new() { Type = "item", Id = 2 },
            }
        });

        Assert.False(result.Ready);
        // Should have exactly 1 collection + 1 category requirement, not 2 of each
        Assert.Equal(2, result.Requirements.Count);
    }

    [Fact]
    public async Task Preflight_Publish_Category_WithPrivateParentCategory_ReturnsParentRequirement()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = "my-ws" };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var parent = new Category { Id = 1, Name = "Parent", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Private };
        var child = new Category { Id = 2, Name = "Child", WorkspaceId = 1, CollectionId = 1, ParentCategoryId = 1, Visibility = Visibility.Private };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(2, 1)).ReturnsAsync(child);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, 1)).ReturnsAsync(new List<Category> { parent, child });

        var result = await _service.PreflightAsync(1, new PreflightRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "category", Id = 2 } }
        });

        Assert.False(result.Ready);
        Assert.Single(result.Requirements);
        Assert.IsType<CategoryNotPublicRequirement>(result.Requirements[0]);
        Assert.Equal(1, ((CategoryNotPublicRequirement)result.Requirements[0]).CategoryId);
    }

    [Fact]
    public async Task Preflight_Publish_Collection_ReturnsOnlySlugIfNeeded()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = null };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Private };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);

        var result = await _service.PreflightAsync(1, new PreflightRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "collection", Id = 1 } }
        });

        Assert.False(result.Ready);
        Assert.Single(result.Requirements);
        Assert.IsType<WorkspaceSlugRequiredRequirement>(result.Requirements[0]);
    }

    #endregion

    #region Preflight — Unpublish

    [Fact]
    public async Task Preflight_Unpublish_Category_ReturnsImpactWarning()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = "my-ws" };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var category = new Category { Id = 1, Name = "Cat", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, CategoryId = 1, Visibility = Visibility.Public };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(category);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, 1)).ReturnsAsync(new List<Category> { category });
        _mockItemRepository.Setup(r => r.GetByCollectionIdAsync(1, 1)).ReturnsAsync(new List<Item> { item });

        var result = await _service.PreflightAsync(1, new PreflightRequest
        {
            Action = PublishAction.Unpublish,
            Entities = new List<EntityRef> { new() { Type = "category", Id = 1 } }
        });

        Assert.False(result.Ready);
        Assert.Single(result.Requirements);
        var req = Assert.IsType<UnpublishWillHideChildrenRequirement>(result.Requirements[0]);
        Assert.Equal("category", req.EntityType);
        Assert.Equal(1, req.AffectedPublicItems);
    }

    [Fact]
    public async Task Preflight_Unpublish_Item_AlwaysReady()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = "my-ws" };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockItemRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(item);

        var result = await _service.PreflightAsync(1, new PreflightRequest
        {
            Action = PublishAction.Unpublish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } }
        });

        Assert.True(result.Ready);
        Assert.Empty(result.Requirements);
    }

    #endregion
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test backend/tests/backend.tests --filter "FullyQualifiedName~PublishManagerServiceTests.Preflight"`
Expected: FAIL — `NotImplementedException`

- [ ] **Step 3: Implement preflight logic**

Replace the `PreflightAsync` method in `backend/src/backend/Services/PublishManagerService.cs`:

```csharp
    public async Task<PreflightResponse> PreflightAsync(int workspaceId, PreflightRequest request)
    {
        var workspace = await _workspaceRepository.GetByIdAsync(workspaceId);
        if (workspace == null)
            throw new InvalidOperationException($"Workspace {workspaceId} not found");

        var requirements = new List<PublishRequirement>();

        if (request.Action == PublishAction.Publish)
        {
            await CollectPublishRequirements(workspaceId, workspace, request.Entities, requirements);
        }
        else
        {
            await CollectUnpublishRequirements(workspaceId, request.Entities, requirements);
        }

        return new PreflightResponse
        {
            Ready = requirements.Count == 0,
            Requirements = requirements,
        };
    }

    private async Task CollectPublishRequirements(int workspaceId, Workspace workspace, List<EntityRef> entities, List<PublishRequirement> requirements)
    {
        // Track already-checked IDs to deduplicate
        var checkedCollectionIds = new HashSet<int>();
        var checkedCategoryIds = new HashSet<int>();
        bool slugChecked = false;

        // Check slug requirement once
        if (workspace.Slug == null)
        {
            requirements.Add(new WorkspaceSlugRequiredRequirement
            {
                WorkspaceId = workspace.Id,
                WorkspaceName = workspace.Name,
            });
            slugChecked = true;
        }

        foreach (var entity in entities)
        {
            switch (entity.Type)
            {
                case "item":
                {
                    var item = await _itemRepository.GetByIdAsync(entity.Id, workspaceId);
                    if (item == null) continue;

                    // Check collection
                    if (!checkedCollectionIds.Contains(item.CollectionId))
                    {
                        var collection = await _collectionRepository.GetByIdAsync(item.CollectionId, workspaceId);
                        if (collection != null && collection.Visibility == Visibility.Private)
                        {
                            requirements.Add(new CollectionNotPublicRequirement
                            {
                                CollectionId = collection.Id,
                                CollectionName = collection.Name,
                            });
                        }
                        checkedCollectionIds.Add(item.CollectionId);
                    }

                    // Check category
                    if (item.CategoryId.HasValue && !checkedCategoryIds.Contains(item.CategoryId.Value))
                    {
                        var allCategories = (await _categoryRepository.GetByCollectionAsync(item.CollectionId, workspaceId)).ToList();
                        var categoryLookup = allCategories.ToDictionary(c => c.Id);

                        CheckCategoryChain(item.CategoryId.Value, categoryLookup, checkedCategoryIds, requirements);
                    }
                    break;
                }
                case "category":
                {
                    var category = await _categoryRepository.GetByIdAsync(entity.Id, workspaceId);
                    if (category == null) continue;

                    // Check collection
                    if (!checkedCollectionIds.Contains(category.CollectionId))
                    {
                        var collection = await _collectionRepository.GetByIdAsync(category.CollectionId, workspaceId);
                        if (collection != null && collection.Visibility == Visibility.Private)
                        {
                            requirements.Add(new CollectionNotPublicRequirement
                            {
                                CollectionId = collection.Id,
                                CollectionName = collection.Name,
                            });
                        }
                        checkedCollectionIds.Add(category.CollectionId);
                    }

                    // Check parent category chain (not the entity itself)
                    if (category.ParentCategoryId.HasValue && !checkedCategoryIds.Contains(category.ParentCategoryId.Value))
                    {
                        var allCategories = (await _categoryRepository.GetByCollectionAsync(category.CollectionId, workspaceId)).ToList();
                        var categoryLookup = allCategories.ToDictionary(c => c.Id);

                        CheckCategoryChain(category.ParentCategoryId.Value, categoryLookup, checkedCategoryIds, requirements);
                    }
                    break;
                }
                case "collection":
                {
                    // Collections have no parent entities to check — only slug (already checked)
                    break;
                }
            }
        }
    }

    private static void CheckCategoryChain(int categoryId, IDictionary<int, Category> categoryLookup, HashSet<int> checkedCategoryIds, List<PublishRequirement> requirements)
    {
        if (checkedCategoryIds.Contains(categoryId)) return;
        checkedCategoryIds.Add(categoryId);

        if (!categoryLookup.TryGetValue(categoryId, out var category)) return;

        // Check parent first (ancestors before descendants)
        if (category.ParentCategoryId.HasValue)
        {
            CheckCategoryChain(category.ParentCategoryId.Value, categoryLookup, checkedCategoryIds, requirements);
        }

        if (category.Visibility == Visibility.Private)
        {
            requirements.Add(new CategoryNotPublicRequirement
            {
                CategoryId = category.Id,
                CategoryName = category.Name,
            });
        }
    }

    private async Task CollectUnpublishRequirements(int workspaceId, List<EntityRef> entities, List<PublishRequirement> requirements)
    {
        foreach (var entity in entities)
        {
            switch (entity.Type)
            {
                case "item":
                    // Items have no children — unpublishing is always ready
                    break;

                case "category":
                {
                    var category = await _categoryRepository.GetByIdAsync(entity.Id, workspaceId);
                    if (category == null) continue;

                    var collection = await _collectionRepository.GetByIdAsync(category.CollectionId, workspaceId);
                    if (collection == null) continue;

                    var allCategories = (await _categoryRepository.GetByCollectionAsync(collection.Id, workspaceId)).ToList();
                    var items = (await _itemRepository.GetByCollectionIdAsync(collection.Id, workspaceId)).ToList();

                    // Compute effective visibility to count truly public entities
                    ComputeEffectiveVisibility(allCategories, collection);
                    ComputeEffectiveVisibility(items, collection, allCategories);

                    var childCategories = allCategories.Where(c => c.Id != category.Id).ToList();
                    var affectedItems = items.Count(i => i.EffectiveIsPublic);
                    var affectedCategories = childCategories.Count(c => c.EffectiveIsPublic);

                    if (affectedItems > 0 || affectedCategories > 0)
                    {
                        requirements.Add(new UnpublishWillHideChildrenRequirement
                        {
                            EntityType = "category",
                            EntityId = category.Id,
                            EntityName = category.Name,
                            AffectedPublicItems = affectedItems,
                            AffectedPublicCategories = affectedCategories,
                        });
                    }
                    break;
                }

                case "collection":
                {
                    var collection = await _collectionRepository.GetByIdAsync(entity.Id, workspaceId);
                    if (collection == null) continue;

                    var allCategories = (await _categoryRepository.GetByCollectionAsync(collection.Id, workspaceId)).ToList();
                    var items = (await _itemRepository.GetByCollectionIdAsync(collection.Id, workspaceId)).ToList();

                    ComputeEffectiveVisibility(allCategories, collection);
                    ComputeEffectiveVisibility(items, collection, allCategories);

                    var affectedItems = items.Count(i => i.EffectiveIsPublic);
                    var affectedCategories = allCategories.Count(c => c.EffectiveIsPublic);

                    if (affectedItems > 0 || affectedCategories > 0)
                    {
                        requirements.Add(new UnpublishWillHideChildrenRequirement
                        {
                            EntityType = "collection",
                            EntityId = collection.Id,
                            EntityName = collection.Name,
                            AffectedPublicItems = affectedItems,
                            AffectedPublicCategories = affectedCategories,
                        });
                    }
                    break;
                }
            }
        }
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test backend/tests/backend.tests --filter "FullyQualifiedName~PublishManagerServiceTests"`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add backend/src/backend/Services/PublishManagerService.cs backend/tests/backend.tests/Services/PublishManagerServiceTests.cs
git commit -m "feat: implement PublishManagerService preflight logic"
```

---

### Task 5: Backend PublishManagerService — Execute Logic

Add atomic execute to the service. Re-validates requirements, applies all visibility changes, handles slug setup.

**Files:**
- Modify: `backend/tests/backend.tests/Services/PublishManagerServiceTests.cs`
- Modify: `backend/src/backend/Services/PublishManagerService.cs`

- [ ] **Step 1: Write failing tests for execute**

Add to `backend/tests/backend.tests/Services/PublishManagerServiceTests.cs`:

```csharp
    #region Execute — Publish

    [Fact]
    public async Task Execute_Publish_Item_WithResolutions_Succeeds()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = null };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Private };
        var category = new Category { Id = 1, Name = "Cat", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Private };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, CategoryId = 1, Visibility = Visibility.Private };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockWorkspaceRepository.Setup(r => r.IsSlugTakenAsync("my-ws", 1)).ReturnsAsync(false);
        _mockItemRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(item);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(category);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, 1)).ReturnsAsync(new List<Category> { category });

        var result = await _service.ExecuteAsync(1, new ExecuteRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } },
            Resolutions = new List<PublishResolution>
            {
                new WorkspaceSlugResolution { Slug = "my-ws" },
                new CollectionNotPublicResolution { CollectionId = 1 },
                new CategoryNotPublicResolution { CategoryId = 1 },
            }
        });

        Assert.True(result.Success);
        Assert.Single(result.Changed);
        Assert.Equal("item", result.Changed[0].Type);
        Assert.Equal(2, result.Promoted.Count);
        Assert.Equal("my-ws", result.WorkspaceSlugSet);

        // Verify visibility was set
        Assert.Equal(Visibility.Public, item.Visibility);
        Assert.Equal(Visibility.Public, collection.Visibility);
        Assert.Equal(Visibility.Public, category.Visibility);
    }

    [Fact]
    public async Task Execute_Publish_MissingResolution_Fails()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = null };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Private };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Private };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockItemRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(item);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);

        var result = await _service.ExecuteAsync(1, new ExecuteRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } },
            Resolutions = new List<PublishResolution>() // Missing resolutions
        });

        Assert.False(result.Success);
        Assert.NotNull(result.Error);
        Assert.NotNull(result.Requirements);
        Assert.NotEmpty(result.Requirements!);
    }

    [Fact]
    public async Task Execute_Publish_SlugTaken_Fails()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = null };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Private };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockWorkspaceRepository.Setup(r => r.IsSlugTakenAsync("taken-slug", 1)).ReturnsAsync(true);
        _mockItemRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(item);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);

        var result = await _service.ExecuteAsync(1, new ExecuteRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } },
            Resolutions = new List<PublishResolution>
            {
                new WorkspaceSlugResolution { Slug = "taken-slug" },
            }
        });

        Assert.False(result.Success);
        Assert.Contains("already taken", result.Error!);
    }

    [Fact]
    public async Task Execute_Publish_Category_PromotesParentCategoriesAndCollection()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = "my-ws" };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Private };
        var parent = new Category { Id = 1, Name = "Parent", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Private };
        var child = new Category { Id = 2, Name = "Child", WorkspaceId = 1, CollectionId = 1, ParentCategoryId = 1, Visibility = Visibility.Private };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(2, 1)).ReturnsAsync(child);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, 1)).ReturnsAsync(new List<Category> { parent, child });
        _mockItemRepository.Setup(r => r.GetByCollectionIdAsync(1, 1)).ReturnsAsync(new List<Item>());

        var result = await _service.ExecuteAsync(1, new ExecuteRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "category", Id = 2 } },
            Resolutions = new List<PublishResolution>
            {
                new CollectionNotPublicResolution { CollectionId = 1 },
                new CategoryNotPublicResolution { CategoryId = 1 },
            }
        });

        Assert.True(result.Success);
        Assert.Single(result.Changed);
        Assert.Equal("category", result.Changed[0].Type);
        Assert.Equal(2, result.Promoted.Count); // collection + parent category
        Assert.Equal(Visibility.Public, parent.Visibility);
        Assert.Equal(Visibility.Public, child.Visibility);
        Assert.Equal(Visibility.Public, collection.Visibility);
    }

    #endregion

    #region Execute — Unpublish

    [Fact]
    public async Task Execute_Unpublish_Item_Succeeds()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = "my-ws" };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockItemRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(item);

        var result = await _service.ExecuteAsync(1, new ExecuteRequest
        {
            Action = PublishAction.Unpublish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } },
            Resolutions = new List<PublishResolution>()
        });

        Assert.True(result.Success);
        Assert.Single(result.Changed);
        Assert.Equal(Visibility.Private, item.Visibility);
    }

    [Fact]
    public async Task Execute_Unpublish_Category_WithAcknowledgment_Succeeds()
    {
        var workspace = new Workspace { Id = 1, Name = "WS", Slug = "my-ws" };
        var collection = new Collection { Id = 1, Name = "Col", WorkspaceId = 1, Slug = "col", Visibility = Visibility.Public };
        var category = new Category { Id = 1, Name = "Cat", WorkspaceId = 1, CollectionId = 1, Visibility = Visibility.Public };
        var item = new Item { Id = 1, Name = "Item", WorkspaceId = 1, CollectionId = 1, CategoryId = 1, Visibility = Visibility.Public };

        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(workspace);
        _mockCategoryRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(category);
        _mockCollectionRepository.Setup(r => r.GetByIdAsync(1, 1)).ReturnsAsync(collection);
        _mockCategoryRepository.Setup(r => r.GetByCollectionAsync(1, 1)).ReturnsAsync(new List<Category> { category });
        _mockItemRepository.Setup(r => r.GetByCollectionIdAsync(1, 1)).ReturnsAsync(new List<Item> { item });

        var result = await _service.ExecuteAsync(1, new ExecuteRequest
        {
            Action = PublishAction.Unpublish,
            Entities = new List<EntityRef> { new() { Type = "category", Id = 1 } },
            Resolutions = new List<PublishResolution>
            {
                new UnpublishWillHideChildrenResolution { EntityType = "category", EntityId = 1 },
            }
        });

        Assert.True(result.Success);
        Assert.Single(result.Changed);
        Assert.Equal(Visibility.Private, category.Visibility);
    }

    #endregion
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test backend/tests/backend.tests --filter "FullyQualifiedName~PublishManagerServiceTests.Execute"`
Expected: FAIL — `NotImplementedException`

- [ ] **Step 3: Implement execute logic**

Replace the `ExecuteAsync` method in `backend/src/backend/Services/PublishManagerService.cs`:

```csharp
    public async Task<ExecuteResponse> ExecuteAsync(int workspaceId, ExecuteRequest request)
    {
        // Re-run preflight to get current requirements
        var preflight = await PreflightAsync(workspaceId, new PreflightRequest
        {
            Action = request.Action,
            Entities = request.Entities,
        });

        // Validate that all requirements have matching resolutions
        if (!preflight.Ready)
        {
            var unresolved = FindUnresolvedRequirements(preflight.Requirements, request.Resolutions);
            if (unresolved.Count > 0)
            {
                return new ExecuteResponse
                {
                    Success = false,
                    Error = "Not all requirements are resolved",
                    Requirements = preflight.Requirements,
                };
            }
        }

        // Handle slug resolution if present
        var slugResolution = request.Resolutions.OfType<WorkspaceSlugResolution>().FirstOrDefault();
        string? workspaceSlugSet = null;
        if (slugResolution != null)
        {
            var workspace = await _workspaceRepository.GetByIdAsync(workspaceId);
            if (workspace == null)
                return new ExecuteResponse { Success = false, Error = "Workspace not found" };

            if (await _workspaceRepository.IsSlugTakenAsync(slugResolution.Slug, workspaceId))
            {
                return new ExecuteResponse
                {
                    Success = false,
                    Error = $"Slug '{slugResolution.Slug}' is already taken",
                    Requirements = preflight.Requirements,
                };
            }

            workspace.Slug = slugResolution.Slug;
            await _workspaceRepository.UpdateAsync(workspace);
            workspaceSlugSet = slugResolution.Slug;
        }

        var changed = new List<ChangedEntityInfo>();
        var promoted = new List<ChangedEntityInfo>();

        if (request.Action == PublishAction.Publish)
        {
            await ExecutePublish(workspaceId, request.Entities, changed, promoted);
        }
        else
        {
            await ExecuteUnpublish(workspaceId, request.Entities, changed);
        }

        return new ExecuteResponse
        {
            Success = true,
            Changed = changed,
            Promoted = promoted,
            WorkspaceSlugSet = workspaceSlugSet,
        };
    }

    private async Task ExecutePublish(int workspaceId, List<EntityRef> entities, List<ChangedEntityInfo> changed, List<ChangedEntityInfo> promoted)
    {
        var promotedCollectionIds = new HashSet<int>();
        var promotedCategoryIds = new HashSet<int>();

        foreach (var entity in entities)
        {
            switch (entity.Type)
            {
                case "item":
                {
                    var item = await _itemRepository.GetByIdAsync(entity.Id, workspaceId);
                    if (item == null) continue;

                    var collection = await _collectionRepository.GetByIdAsync(item.CollectionId, workspaceId);
                    if (collection == null) continue;

                    // Promote collection if needed
                    if (collection.Visibility == Visibility.Private && promotedCollectionIds.Add(collection.Id))
                    {
                        collection.Visibility = Visibility.Public;
                        promoted.Add(new ChangedEntityInfo { Type = "collection", Id = collection.Id, Name = collection.Name });
                        await _collectionRepository.UpdateAsync(collection.Id, collection, workspaceId);
                    }

                    // Promote category chain if needed
                    if (item.CategoryId.HasValue)
                    {
                        var allCategories = (await _categoryRepository.GetByCollectionAsync(item.CollectionId, workspaceId)).ToList();
                        var categoryLookup = allCategories.ToDictionary(c => c.Id);
                        PromoteParentCategories(item.CategoryId.Value, categoryLookup, promotedCategoryIds, promoted);

                        // Save any promoted categories
                        foreach (var cat in allCategories.Where(c => promotedCategoryIds.Contains(c.Id)))
                        {
                            await _categoryRepository.UpdateAsync(cat.Id, cat, workspaceId);
                        }
                    }

                    item.Visibility = Visibility.Public;
                    await _itemRepository.UpdateAsync(item.Id ?? 0, item, workspaceId);
                    changed.Add(new ChangedEntityInfo { Type = "item", Id = item.Id ?? 0, Name = item.Name });
                    break;
                }
                case "category":
                {
                    var allCategories = (await _categoryRepository.GetByCollectionAsync(
                        (await _categoryRepository.GetByIdAsync(entity.Id, workspaceId))!.CollectionId, workspaceId)).ToList();
                    var categoryLookup = allCategories.ToDictionary(c => c.Id);
                    var category = categoryLookup[entity.Id];

                    var collection = await _collectionRepository.GetByIdAsync(category.CollectionId, workspaceId);
                    if (collection == null) continue;

                    // Promote collection if needed
                    if (collection.Visibility == Visibility.Private && promotedCollectionIds.Add(collection.Id))
                    {
                        collection.Visibility = Visibility.Public;
                        promoted.Add(new ChangedEntityInfo { Type = "collection", Id = collection.Id, Name = collection.Name });
                        await _collectionRepository.UpdateAsync(collection.Id, collection, workspaceId);
                    }

                    // Promote parent categories
                    PromoteParentCategories(category, categoryLookup, promoted);
                    foreach (var cat in allCategories)
                    {
                        await _categoryRepository.UpdateAsync(cat.Id, cat, workspaceId);
                    }

                    category.Visibility = Visibility.Public;
                    await _categoryRepository.UpdateAsync(category.Id, category, workspaceId);
                    changed.Add(new ChangedEntityInfo { Type = "category", Id = category.Id, Name = category.Name });
                    break;
                }
                case "collection":
                {
                    var collection = await _collectionRepository.GetByIdAsync(entity.Id, workspaceId);
                    if (collection == null) continue;

                    collection.Visibility = Visibility.Public;
                    await _collectionRepository.UpdateAsync(collection.Id, collection, workspaceId);
                    changed.Add(new ChangedEntityInfo { Type = "collection", Id = collection.Id, Name = collection.Name });
                    break;
                }
            }
        }
    }

    private async Task ExecuteUnpublish(int workspaceId, List<EntityRef> entities, List<ChangedEntityInfo> changed)
    {
        foreach (var entity in entities)
        {
            switch (entity.Type)
            {
                case "item":
                {
                    var item = await _itemRepository.GetByIdAsync(entity.Id, workspaceId);
                    if (item == null) continue;
                    item.Visibility = Visibility.Private;
                    await _itemRepository.UpdateAsync(item.Id ?? 0, item, workspaceId);
                    changed.Add(new ChangedEntityInfo { Type = "item", Id = item.Id ?? 0, Name = item.Name });
                    break;
                }
                case "category":
                {
                    var category = await _categoryRepository.GetByIdAsync(entity.Id, workspaceId);
                    if (category == null) continue;
                    category.Visibility = Visibility.Private;
                    await _categoryRepository.UpdateAsync(category.Id, category, workspaceId);
                    changed.Add(new ChangedEntityInfo { Type = "category", Id = category.Id, Name = category.Name });
                    break;
                }
                case "collection":
                {
                    var collection = await _collectionRepository.GetByIdAsync(entity.Id, workspaceId);
                    if (collection == null) continue;
                    collection.Visibility = Visibility.Private;
                    await _collectionRepository.UpdateAsync(collection.Id, collection, workspaceId);
                    changed.Add(new ChangedEntityInfo { Type = "collection", Id = collection.Id, Name = collection.Name });
                    break;
                }
            }
        }
    }

    private static List<PublishRequirement> FindUnresolvedRequirements(List<PublishRequirement> requirements, List<PublishResolution> resolutions)
    {
        var unresolved = new List<PublishRequirement>();

        foreach (var req in requirements)
        {
            bool resolved = req switch
            {
                WorkspaceSlugRequiredRequirement => resolutions.Any(r => r is WorkspaceSlugResolution),
                CollectionNotPublicRequirement c => resolutions.Any(r => r is CollectionNotPublicResolution cr && cr.CollectionId == c.CollectionId),
                CategoryNotPublicRequirement c => resolutions.Any(r => r is CategoryNotPublicResolution cr && cr.CategoryId == c.CategoryId),
                UnpublishWillHideChildrenRequirement u => resolutions.Any(r => r is UnpublishWillHideChildrenResolution ur && ur.EntityId == u.EntityId),
                _ => false,
            };

            if (!resolved) unresolved.Add(req);
        }

        return unresolved;
    }

    private static void PromoteParentCategories(int categoryId, IDictionary<int, Category> categoryLookup, HashSet<int> promotedIds, List<ChangedEntityInfo> promoted)
    {
        if (!categoryLookup.TryGetValue(categoryId, out var category)) return;

        if (category.ParentCategoryId.HasValue)
        {
            PromoteParentCategories(category.ParentCategoryId.Value, categoryLookup, promotedIds, promoted);
        }

        if (category.Visibility == Visibility.Private && promotedIds.Add(category.Id))
        {
            category.Visibility = Visibility.Public;
            promoted.Add(new ChangedEntityInfo { Type = "category", Id = category.Id, Name = category.Name });
        }
    }
```

- [ ] **Step 4: Run all tests to verify they pass**

Run: `dotnet test backend/tests/backend.tests --filter "FullyQualifiedName~PublishManagerServiceTests"`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add backend/src/backend/Services/PublishManagerService.cs backend/tests/backend.tests/Services/PublishManagerServiceTests.cs
git commit -m "feat: implement PublishManagerService execute logic"
```

---

### Task 6: Backend PublishManagerController

Create the controller with two endpoints.

**Files:**
- Create: `backend/src/backend/Controllers/PublishManagerController.cs`
- Create: `backend/tests/backend.tests/Controllers/PublishManagerControllerTests.cs`

- [ ] **Step 1: Write failing controller tests**

Create `backend/tests/backend.tests/Controllers/PublishManagerControllerTests.cs`:

```csharp
using backend.DTOs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.Services;
using System.Security.Claims;

namespace backend.tests.Controllers;

[Trait("Category", "Unit")]
public class PublishManagerControllerTests
{
    private const int TestWorkspaceId = 1;
    private const int TestUserId = 100;

    private readonly Mock<IPublishManagerService> _mockService = new();
    private readonly PublishManagerController _controller;

    public PublishManagerControllerTests()
    {
        _controller = new PublishManagerController(_mockService.Object);
        SetupAuth(TestWorkspaceId, TestUserId);
    }

    private void SetupAuth(int workspaceId, int userId)
    {
        var claims = new[]
        {
            new Claim("workspace_id", workspaceId.ToString()),
            new Claim("sub", userId.ToString()),
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Email, "test@example.com"),
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = principal }
        };
    }

    [Fact]
    public async Task Preflight_ReturnsOkWithPreflightResponse()
    {
        var request = new PreflightRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } }
        };

        _mockService.Setup(s => s.PreflightAsync(TestWorkspaceId, request))
            .ReturnsAsync(new PreflightResponse { Ready = true });

        var result = await _controller.Preflight(TestWorkspaceId, request);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PreflightResponse>(ok.Value);
        Assert.True(response.Ready);
    }

    [Fact]
    public async Task Preflight_WrongWorkspace_ReturnsForbid()
    {
        var request = new PreflightRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } }
        };

        var result = await _controller.Preflight(999, request);

        Assert.IsType<ForbidResult>(result);
    }

    [Fact]
    public async Task Execute_ReturnsOkWithExecuteResponse()
    {
        var request = new ExecuteRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } },
            Resolutions = new List<PublishResolution>()
        };

        _mockService.Setup(s => s.ExecuteAsync(TestWorkspaceId, request))
            .ReturnsAsync(new ExecuteResponse { Success = true });

        var result = await _controller.Execute(TestWorkspaceId, request);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<ExecuteResponse>(ok.Value);
        Assert.True(response.Success);
    }

    [Fact]
    public async Task Execute_WrongWorkspace_ReturnsForbid()
    {
        var request = new ExecuteRequest
        {
            Action = PublishAction.Publish,
            Entities = new List<EntityRef> { new() { Type = "item", Id = 1 } },
            Resolutions = new List<PublishResolution>()
        };

        var result = await _controller.Execute(999, request);

        Assert.IsType<ForbidResult>(result);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test backend/tests/backend.tests --filter "FullyQualifiedName~PublishManagerControllerTests"`
Expected: FAIL — `PublishManagerController` does not exist

- [ ] **Step 3: Write the controller**

Create `backend/src/backend/Controllers/PublishManagerController.cs`:

```csharp
using backend.DTOs;
using OneBigHead.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/workspaces/{workspaceId}/publish")]
[Authorize]
public class PublishManagerController : ApiControllerBase
{
    private readonly IPublishManagerService _publishManagerService;

    public PublishManagerController(IPublishManagerService publishManagerService)
    {
        _publishManagerService = publishManagerService;
    }

    [HttpPost("preflight")]
    public async Task<IActionResult> Preflight(int workspaceId, [FromBody] PreflightRequest request)
    {
        var wsId = GetWorkspaceId();
        if (wsId != workspaceId) return Forbid();

        var result = await _publishManagerService.PreflightAsync(workspaceId, request);
        return Ok(result);
    }

    [HttpPost("execute")]
    public async Task<IActionResult> Execute(int workspaceId, [FromBody] ExecuteRequest request)
    {
        var wsId = GetWorkspaceId();
        if (wsId != workspaceId) return Forbid();

        var result = await _publishManagerService.ExecuteAsync(workspaceId, request);
        return Ok(result);
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test backend/tests/backend.tests --filter "FullyQualifiedName~PublishManagerControllerTests"`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add backend/src/backend/Controllers/PublishManagerController.cs backend/tests/backend.tests/Controllers/PublishManagerControllerTests.cs
git commit -m "feat: add PublishManagerController with preflight and execute endpoints"
```

---

### Task 7: Backend DI Registration and Cleanup

Replace `IVisibilityService` with `IPublishManagerService` in DI, update consuming controllers, delete old files.

**Files:**
- Modify: `backend/src/backend/Program.cs:64,88`
- Modify: `backend/src/backend/Controllers/ItemsController.cs`
- Modify: `backend/src/backend/Controllers/CategoriesController.cs`
- Modify: `backend/src/backend/Controllers/PublicController.cs`
- Delete: `backend/src/backend/Controllers/PublishController.cs`
- Delete: `backend/src/backend/Services/IVisibilityService.cs`
- Delete: `backend/src/backend/Services/VisibilityService.cs`
- Delete: `backend/src/backend/Services/PublishResult.cs`
- Delete: `backend/src/backend/DTOs/PublishRequests.cs`
- Delete: `backend/tests/backend.tests/Controllers/PublishControllerTests.cs`
- Delete: `backend/tests/backend.tests/Services/VisibilityServiceTests.cs`

- [ ] **Step 1: Update DI registration in Program.cs**

Replace `IVisibilityService` registrations in `backend/src/backend/Program.cs`:

Line 64: change `builder.Services.AddTracingDecorator<IVisibilityService, VisibilityService>(appSource);`
to `builder.Services.AddTracingDecorator<IPublishManagerService, PublishManagerService>(appSource);`

Line 88: change `builder.Services.AddScoped<IVisibilityService, VisibilityService>();`
to `builder.Services.AddScoped<IPublishManagerService, PublishManagerService>();`

Add the using at the top if not already present: `using OneBigHead.Server.Services;`

- [ ] **Step 2: Update ItemsController**

In `backend/src/backend/Controllers/ItemsController.cs`:

Replace `IVisibilityService` with `IPublishManagerService` in the field declaration, constructor parameter, and constructor assignment. Keep all `ComputeEffectiveVisibility` calls — rename from `_visibilityService` to `_publishManagerService`.

- [ ] **Step 3: Update CategoriesController**

In `backend/src/backend/Controllers/CategoriesController.cs`:

Same pattern as ItemsController — replace `IVisibilityService` → `IPublishManagerService`, rename field `_visibilityService` → `_publishManagerService`.

- [ ] **Step 4: Update PublicController**

In `backend/src/backend/Controllers/PublicController.cs`:

Same pattern — replace `IVisibilityService` → `IPublishManagerService`, rename field.

- [ ] **Step 5: Delete old files**

Delete these files:
- `backend/src/backend/Controllers/PublishController.cs`
- `backend/src/backend/Services/IVisibilityService.cs`
- `backend/src/backend/Services/VisibilityService.cs`
- `backend/src/backend/Services/PublishResult.cs`
- `backend/src/backend/DTOs/PublishRequests.cs`
- `backend/tests/backend.tests/Controllers/PublishControllerTests.cs`
- `backend/tests/backend.tests/Services/VisibilityServiceTests.cs`

- [ ] **Step 6: Verify the project builds and all tests pass**

Run: `dotnet build backend/src/backend`
Expected: Build succeeded

Run: `dotnet test backend/tests/backend.tests`
Expected: All tests PASS

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor: replace IVisibilityService with IPublishManagerService, delete old publish infrastructure"
```

---

### Task 8: Frontend Types and API Module

Create new TypeScript types and the API module for the centralized publish manager.

**Files:**
- Modify: `frontend/src/utils/types.ts`
- Create: `frontend/src/api/publishManager.ts`
- Create: `frontend/tests/api/publishManager.test.ts`

- [ ] **Step 1: Add new types to types.ts**

Add to `frontend/src/utils/types.ts` (replace the old publish-related types):

Remove these types: `PublishResponse`, `BulkPublishResponse`, `UnpublishResponse`, `BulkUnpublishResponse`, `UnpublishPreviewResponse`, `PublishedEntityInfo`.

Add these types:

```typescript
// === Publish Manager Types ===

export interface EntityRef {
  type: 'item' | 'category' | 'collection';
  id: number;
}

export interface ChangedEntityInfo {
  type: string;
  id: number;
  name: string;
}

// Preflight

export interface PreflightRequest {
  action: 'publish' | 'unpublish';
  entities: EntityRef[];
}

export interface PreflightResponse {
  ready: boolean;
  requirements: PublishRequirement[];
}

export type PublishRequirement =
  | WorkspaceSlugRequiredRequirement
  | CollectionNotPublicRequirement
  | CategoryNotPublicRequirement
  | UnpublishWillHideChildrenRequirement;

export interface WorkspaceSlugRequiredRequirement {
  kind: 'workspace-slug-required';
  workspaceId: number;
  workspaceName: string;
}

export interface CollectionNotPublicRequirement {
  kind: 'collection-not-public';
  collectionId: number;
  collectionName: string;
}

export interface CategoryNotPublicRequirement {
  kind: 'category-not-public';
  categoryId: number;
  categoryName: string;
}

export interface UnpublishWillHideChildrenRequirement {
  kind: 'unpublish-will-hide-children';
  entityType: string;
  entityId: number;
  entityName: string;
  affectedPublicItems: number;
  affectedPublicCategories: number;
}

// Execute

export type PublishResolution =
  | WorkspaceSlugResolution
  | CollectionNotPublicResolution
  | CategoryNotPublicResolution
  | UnpublishWillHideChildrenResolution;

export interface WorkspaceSlugResolution {
  kind: 'workspace-slug-required';
  slug: string;
}

export interface CollectionNotPublicResolution {
  kind: 'collection-not-public';
  collectionId: number;
}

export interface CategoryNotPublicResolution {
  kind: 'category-not-public';
  categoryId: number;
}

export interface UnpublishWillHideChildrenResolution {
  kind: 'unpublish-will-hide-children';
  entityType: string;
  entityId: number;
}

export interface ExecuteRequest {
  action: 'publish' | 'unpublish';
  entities: EntityRef[];
  resolutions: PublishResolution[];
}

export interface ExecuteResponse {
  success: boolean;
  error?: string;
  changed: ChangedEntityInfo[];
  promoted: ChangedEntityInfo[];
  workspaceSlugSet?: string;
  requirements?: PublishRequirement[];
}

export interface PublishIntent {
  action: 'publish' | 'unpublish';
  entities: EntityRef[];
}
```

- [ ] **Step 2: Create the API module**

Create `frontend/src/api/publishManager.ts`:

```typescript
import { api } from './client';
import type { PreflightResponse, ExecuteRequest, ExecuteResponse, EntityRef } from '../utils/types';

export const publishManagerApi = {
  preflight(workspaceId: number, action: 'publish' | 'unpublish', entities: EntityRef[]): Promise<PreflightResponse> {
    return api.post<PreflightResponse>(`/workspaces/${workspaceId}/publish/preflight`, { action, entities });
  },

  execute(workspaceId: number, request: ExecuteRequest): Promise<ExecuteResponse> {
    return api.post<ExecuteResponse>(`/workspaces/${workspaceId}/publish/execute`, request);
  },
};
```

- [ ] **Step 3: Write API module tests**

Create `frontend/tests/api/publishManager.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { publishManagerApi } from '../../src/api/publishManager';

describe('publishManagerApi', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('preflight', () => {
    it('should POST to correct endpoint with action and entities', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ ready: true, requirements: [] }),
      });

      const result = await publishManagerApi.preflight(1, 'publish', [{ type: 'item', id: 42 }]);

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/workspaces/1/publish/preflight');
      expect(call[1].method).toBe('POST');
      const body = JSON.parse(call[1].body);
      expect(body.action).toBe('publish');
      expect(body.entities).toEqual([{ type: 'item', id: 42 }]);
      expect(result.ready).toBe(true);
    });
  });

  describe('execute', () => {
    it('should POST to correct endpoint with full request', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ success: true, changed: [], promoted: [] }),
      });

      const request = {
        action: 'publish' as const,
        entities: [{ type: 'item' as const, id: 42 }],
        resolutions: [{ kind: 'collection-not-public' as const, collectionId: 5 }],
      };

      const result = await publishManagerApi.execute(1, request);

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/workspaces/1/publish/execute');
      expect(call[1].method).toBe('POST');
      expect(result.success).toBe(true);
    });
  });
});
```

- [ ] **Step 4: Run tests**

Run: `cd frontend && npx vitest run tests/api/publishManager.test.ts`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/utils/types.ts frontend/src/api/publishManager.ts frontend/tests/api/publishManager.test.ts
git commit -m "feat: add frontend publish manager types and API module"
```

---

### Task 9: Frontend PublishContext

Create the context that exposes `requestPublish` and `requestUnpublish` to the entire app.

**Files:**
- Create: `frontend/src/contexts/PublishContext.tsx`
- Create: `frontend/src/contexts/usePublish.ts`
- Modify: `frontend/src/contexts/index.ts`

- [ ] **Step 1: Create PublishContext**

Create `frontend/src/contexts/PublishContext.tsx`:

```typescript
import { createContext, useState, useCallback, type ReactNode } from 'react';
import type { EntityRef, PublishIntent } from '../utils/types';

export interface PublishContextValue {
  requestPublish: (entities: EntityRef[]) => void;
  requestUnpublish: (entities: EntityRef[]) => void;
  pendingIntent: PublishIntent | null;
  clearIntent: () => void;
}

const PublishContext = createContext<PublishContextValue>({
  requestPublish: () => {},
  requestUnpublish: () => {},
  pendingIntent: null,
  clearIntent: () => {},
});

export function PublishProvider({ children }: { children: ReactNode }) {
  const [pendingIntent, setPendingIntent] = useState<PublishIntent | null>(null);

  const requestPublish = useCallback((entities: EntityRef[]) => {
    setPendingIntent({ action: 'publish', entities });
  }, []);

  const requestUnpublish = useCallback((entities: EntityRef[]) => {
    setPendingIntent({ action: 'unpublish', entities });
  }, []);

  const clearIntent = useCallback(() => {
    setPendingIntent(null);
  }, []);

  return (
    <PublishContext.Provider value={{ requestPublish, requestUnpublish, pendingIntent, clearIntent }}>
      {children}
    </PublishContext.Provider>
  );
}

export default PublishContext;
```

- [ ] **Step 2: Create usePublish hook**

Create `frontend/src/contexts/usePublish.ts`:

```typescript
import { useContext } from 'react';
import PublishContext from './PublishContext';
import type { PublishContextValue } from './PublishContext';

export function usePublish(): PublishContextValue {
  return useContext(PublishContext);
}
```

- [ ] **Step 3: Update contexts barrel export**

Add to `frontend/src/contexts/index.ts`:

```typescript
export { usePublish } from './usePublish';
```

- [ ] **Step 4: Verify frontend builds**

Run: `cd frontend && npm run build`
Expected: Build succeeded

- [ ] **Step 5: Commit**

```bash
git add frontend/src/contexts/PublishContext.tsx frontend/src/contexts/usePublish.ts frontend/src/contexts/index.ts
git commit -m "feat: add PublishContext with requestPublish/requestUnpublish"
```

---

### Task 10: Frontend PublishResolver Component

The unified modal that handles the entire publish/unpublish flow. Rendered once at the app level.

**Files:**
- Create: `frontend/src/components/common/PublishResolver.tsx`
- Create: `frontend/tests/PublishResolver.test.tsx`
- Create: `frontend/src/styles/components/publish-resolver.css`

- [ ] **Step 1: Write tests for PublishResolver**

Create `frontend/tests/PublishResolver.test.tsx`. This is a large test file — tests cover:
- Renders nothing when no pending intent
- Calls preflight on mount when intent is set
- Auto-executes when ready=true
- Renders slug input for workspace-slug-required
- Renders acknowledgment checkboxes for collection-not-public and category-not-public
- Renders impact warning for unpublish-will-hide-children
- Submit disabled until all requirements resolved
- Calls execute with correct resolutions on submit
- Handles execute failure (re-renders with fresh requirements)
- Shows toast on success
- Calls onComplete callback (for cache invalidation)

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { PublishResolver } from '../../src/components/common/PublishResolver';
import type { PreflightResponse, ExecuteResponse, PublishIntent } from '../../src/utils/types';

const mockPreflight = vi.fn();
const mockExecute = vi.fn();
const mockShowToast = vi.fn();
const mockClearIntent = vi.fn();
const mockOnComplete = vi.fn();
const mockRefetchUser = vi.fn();

vi.mock('../../src/api/publishManager', () => ({
  publishManagerApi: {
    preflight: (...args: unknown[]) => mockPreflight(...args),
    execute: (...args: unknown[]) => mockExecute(...args),
  },
}));

vi.mock('../../src/contexts/useToast', () => ({
  useToast: () => ({ showToast: mockShowToast }),
}));

vi.mock('../../src/contexts/useUser', () => ({
  useUser: () => ({
    user: { activeWorkspace: { workspaceId: 1, workspaceName: 'Test WS' } },
    refetch: mockRefetchUser,
  }),
}));

describe('PublishResolver', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders nothing when no pending intent', () => {
    const { container } = render(
      <PublishResolver intent={null} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />
    );
    expect(container.innerHTML).toBe('');
  });

  it('auto-executes when preflight returns ready', async () => {
    mockPreflight.mockResolvedValue({ ready: true, requirements: [] });
    mockExecute.mockResolvedValue({ success: true, changed: [{ type: 'item', id: 1, name: 'Test' }], promoted: [] });

    const intent: PublishIntent = { action: 'publish', entities: [{ type: 'item', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    await waitFor(() => {
      expect(mockExecute).toHaveBeenCalled();
    });
    await waitFor(() => {
      expect(mockShowToast).toHaveBeenCalled();
    });
    expect(mockClearIntent).toHaveBeenCalled();
    expect(mockOnComplete).toHaveBeenCalled();
  });

  it('renders slug input for workspace-slug-required requirement', async () => {
    mockPreflight.mockResolvedValue({
      ready: false,
      requirements: [{ kind: 'workspace-slug-required', workspaceId: 1, workspaceName: 'Test WS' }],
    });

    const intent: PublishIntent = { action: 'publish', entities: [{ type: 'item', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    await waitFor(() => {
      expect(screen.getByLabelText('Gallery URL')).toBeInTheDocument();
    });
  });

  it('renders acknowledgment for collection-not-public', async () => {
    mockPreflight.mockResolvedValue({
      ready: false,
      requirements: [{ kind: 'collection-not-public', collectionId: 5, collectionName: 'Vintage Cars' }],
    });

    const intent: PublishIntent = { action: 'publish', entities: [{ type: 'item', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    await waitFor(() => {
      expect(screen.getByText(/Vintage Cars/)).toBeInTheDocument();
    });
  });

  it('renders impact warning for unpublish-will-hide-children', async () => {
    mockPreflight.mockResolvedValue({
      ready: false,
      requirements: [{
        kind: 'unpublish-will-hide-children',
        entityType: 'category',
        entityId: 1,
        entityName: 'Watches',
        affectedPublicItems: 12,
        affectedPublicCategories: 2,
      }],
    });

    const intent: PublishIntent = { action: 'unpublish', entities: [{ type: 'category', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    await waitFor(() => {
      expect(screen.getByText(/12 items/)).toBeInTheDocument();
    });
  });

  it('submit is disabled until all requirements are resolved', async () => {
    mockPreflight.mockResolvedValue({
      ready: false,
      requirements: [
        { kind: 'collection-not-public', collectionId: 5, collectionName: 'Vintage Cars' },
      ],
    });

    const user = userEvent.setup();
    const intent: PublishIntent = { action: 'publish', entities: [{ type: 'item', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /publish/i })).toBeDisabled();
    });

    // Check the acknowledgment checkbox
    const checkbox = await screen.findByRole('checkbox');
    await user.click(checkbox);

    expect(screen.getByRole('button', { name: /publish/i })).toBeEnabled();
  });

  it('calls execute with correct resolutions and shows toast', async () => {
    mockPreflight.mockResolvedValue({
      ready: false,
      requirements: [
        { kind: 'collection-not-public', collectionId: 5, collectionName: 'Vintage Cars' },
      ],
    });
    mockExecute.mockResolvedValue({
      success: true,
      changed: [{ type: 'item', id: 1, name: 'Mustang' }],
      promoted: [{ type: 'collection', id: 5, name: 'Vintage Cars' }],
    });

    const user = userEvent.setup();
    const intent: PublishIntent = { action: 'publish', entities: [{ type: 'item', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    // Resolve the requirement
    const checkbox = await screen.findByRole('checkbox');
    await user.click(checkbox);
    await user.click(screen.getByRole('button', { name: /publish/i }));

    await waitFor(() => {
      expect(mockExecute).toHaveBeenCalledWith(1, expect.objectContaining({
        action: 'publish',
        resolutions: expect.arrayContaining([
          expect.objectContaining({ kind: 'collection-not-public', collectionId: 5 }),
        ]),
      }));
    });

    await waitFor(() => {
      expect(mockShowToast).toHaveBeenCalled();
    });
  });

  it('handles execute failure by re-rendering requirements', async () => {
    mockPreflight.mockResolvedValue({
      ready: false,
      requirements: [{ kind: 'workspace-slug-required', workspaceId: 1, workspaceName: 'Test WS' }],
    });
    mockExecute.mockResolvedValue({
      success: false,
      error: "Slug 'taken' is already taken",
      requirements: [{ kind: 'workspace-slug-required', workspaceId: 1, workspaceName: 'Test WS' }],
    });

    const user = userEvent.setup();
    const intent: PublishIntent = { action: 'publish', entities: [{ type: 'item', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    const input = await screen.findByLabelText('Gallery URL');
    await user.type(input, 'taken');
    await user.click(screen.getByRole('button', { name: /publish/i }));

    await waitFor(() => {
      expect(screen.getByText(/already taken/)).toBeInTheDocument();
    });
  });

  it('cancel clears intent', async () => {
    mockPreflight.mockResolvedValue({
      ready: false,
      requirements: [{ kind: 'collection-not-public', collectionId: 5, collectionName: 'Vintage Cars' }],
    });

    const user = userEvent.setup();
    const intent: PublishIntent = { action: 'publish', entities: [{ type: 'item', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    const cancelBtn = await screen.findByRole('button', { name: /cancel/i });
    await user.click(cancelBtn);

    expect(mockClearIntent).toHaveBeenCalled();
  });

  it('refetches user when workspace slug is set', async () => {
    mockPreflight.mockResolvedValue({ ready: true, requirements: [] });
    mockExecute.mockResolvedValue({
      success: true,
      changed: [{ type: 'item', id: 1, name: 'Test' }],
      promoted: [],
      workspaceSlugSet: 'my-gallery',
    });

    const intent: PublishIntent = { action: 'publish', entities: [{ type: 'item', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    await waitFor(() => {
      expect(mockRefetchUser).toHaveBeenCalled();
    });
  });
});
```

- [ ] **Step 2: Create PublishResolver CSS**

Create `frontend/src/styles/components/publish-resolver.css`:

```css
.publish-resolver__overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.publish-resolver {
  background: var(--color-surface);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-lg);
  max-width: 480px;
  width: 90vw;
}

.publish-resolver__header {
  padding: var(--space-lg) var(--space-lg) 0;
}

.publish-resolver__title {
  margin: 0;
  font-size: 1.1rem;
  font-weight: 600;
}

.publish-resolver__body {
  padding: var(--space-md) var(--space-lg);
}

.publish-resolver__error {
  color: var(--color-danger);
  font-size: 0.9rem;
  margin-bottom: var(--space-md);
}

.publish-resolver__requirement {
  display: flex;
  align-items: flex-start;
  gap: var(--space-sm);
  padding: var(--space-sm) 0;
}

.publish-resolver__requirement label {
  font-size: 0.9rem;
  color: var(--color-text);
  cursor: pointer;
}

.publish-resolver__slug-group {
  margin-bottom: var(--space-md);
}

.publish-resolver__slug-label {
  display: block;
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--color-text-secondary);
  margin-bottom: var(--space-xs);
}

.publish-resolver__slug-input {
  width: 100%;
  padding: var(--space-sm);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  font-size: 0.9rem;
}

.publish-resolver__slug-preview {
  font-size: 0.8rem;
  color: var(--color-text-muted);
  margin-top: var(--space-xs);
}

.publish-resolver__impact {
  background: var(--color-surface-alt);
  border-radius: var(--radius-md);
  padding: var(--space-md);
  margin-bottom: var(--space-sm);
  font-size: 0.9rem;
  color: var(--color-text-secondary);
  line-height: 1.5;
}

.publish-resolver__footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-sm);
  padding: 0 var(--space-lg) var(--space-lg);
}
```

- [ ] **Step 3: Implement PublishResolver component**

Create `frontend/src/components/common/PublishResolver.tsx`:

```typescript
import { useState, useEffect, useCallback } from 'react';
import { publishManagerApi } from '../../api/publishManager';
import { useToast } from '../../contexts/useToast';
import { useUser } from '../../contexts/useUser';
import { isValidSlug } from '../../utils/slugUtils';
import type {
  PublishIntent,
  PublishRequirement,
  PublishResolution,
  PreflightResponse,
  ExecuteResponse,
} from '../../utils/types';
import '../../styles/components/publish-resolver.css';

interface PublishResolverProps {
  intent: PublishIntent | null;
  onClearIntent: () => void;
  onComplete: () => void;
}

export function PublishResolver({ intent, onClearIntent, onComplete }: PublishResolverProps) {
  const { showToast } = useToast();
  const { user, refetch: refetchUser } = useUser();
  const workspaceId = user?.activeWorkspace?.workspaceId;

  const [requirements, setRequirements] = useState<PublishRequirement[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [showModal, setShowModal] = useState(false);

  // Resolution state
  const [slugValue, setSlugValue] = useState('');
  const [acknowledgedCollections, setAcknowledgedCollections] = useState<Set<number>>(new Set());
  const [acknowledgedCategories, setAcknowledgedCategories] = useState<Set<number>>(new Set());
  const [acknowledgedUnpublish, setAcknowledgedUnpublish] = useState<Set<string>>(new Set());

  const resetState = useCallback(() => {
    setRequirements([]);
    setError(null);
    setSlugValue('');
    setAcknowledgedCollections(new Set());
    setAcknowledgedCategories(new Set());
    setAcknowledgedUnpublish(new Set());
    setShowModal(false);
    setLoading(false);
  }, []);

  const buildToastMessage = useCallback((response: ExecuteResponse): string => {
    if (response.changed.length === 0) return 'Done.';
    if (response.changed.length === 1) {
      const action = intent?.action === 'publish' ? 'published' : 'unpublished';
      return `${response.changed[0].name} ${action}.`;
    }
    const action = intent?.action === 'publish' ? 'published' : 'unpublished';
    return `${response.changed.length} items ${action}.`;
  }, [intent]);

  const buildToastDetails = useCallback((response: ExecuteResponse): string | undefined => {
    if (response.promoted.length === 0) return undefined;
    const names = response.promoted.map(p => `'${p.name}'`).join(', ');
    return `Promoted: ${names} are now visible in your gallery.`;
  }, []);

  const doExecute = useCallback(async (resolutions: PublishResolution[]) => {
    if (!intent || !workspaceId) return;

    setLoading(true);
    try {
      const result = await publishManagerApi.execute(workspaceId, {
        action: intent.action,
        entities: intent.entities,
        resolutions,
      });

      if (!result.success) {
        setError(result.error ?? 'Publish failed');
        if (result.requirements) {
          setRequirements(result.requirements);
        }
        setLoading(false);
        return;
      }

      if (result.workspaceSlugSet) {
        await refetchUser();
      }

      showToast(buildToastMessage(result), buildToastDetails(result));
      resetState();
      onClearIntent();
      onComplete();
    } catch {
      setError('An unexpected error occurred');
      setLoading(false);
    }
  }, [intent, workspaceId, refetchUser, showToast, buildToastMessage, buildToastDetails, resetState, onClearIntent, onComplete]);

  // Run preflight when intent changes
  useEffect(() => {
    if (!intent || !workspaceId) {
      resetState();
      return;
    }

    let cancelled = false;

    async function runPreflight() {
      setLoading(true);
      setError(null);

      try {
        const result: PreflightResponse = await publishManagerApi.preflight(
          workspaceId!,
          intent!.action,
          intent!.entities,
        );

        if (cancelled) return;

        if (result.ready) {
          // No requirements — execute immediately
          await doExecute([]);
        } else {
          setRequirements(result.requirements);
          setShowModal(true);
          setLoading(false);
        }
      } catch {
        if (!cancelled) {
          setError('Failed to check publish requirements');
          setShowModal(true);
          setLoading(false);
        }
      }
    }

    runPreflight();
    return () => { cancelled = true; };
  }, [intent, workspaceId]); // eslint-disable-line react-hooks/exhaustive-deps

  const allResolved = useCallback((): boolean => {
    for (const req of requirements) {
      switch (req.kind) {
        case 'workspace-slug-required':
          if (!isValidSlug(slugValue)) return false;
          break;
        case 'collection-not-public':
          if (!acknowledgedCollections.has(req.collectionId)) return false;
          break;
        case 'category-not-public':
          if (!acknowledgedCategories.has(req.categoryId)) return false;
          break;
        case 'unpublish-will-hide-children':
          if (!acknowledgedUnpublish.has(`${req.entityType}-${req.entityId}`)) return false;
          break;
      }
    }
    return true;
  }, [requirements, slugValue, acknowledgedCollections, acknowledgedCategories, acknowledgedUnpublish]);

  const buildResolutions = useCallback((): PublishResolution[] => {
    const resolutions: PublishResolution[] = [];
    for (const req of requirements) {
      switch (req.kind) {
        case 'workspace-slug-required':
          resolutions.push({ kind: 'workspace-slug-required', slug: slugValue });
          break;
        case 'collection-not-public':
          resolutions.push({ kind: 'collection-not-public', collectionId: req.collectionId });
          break;
        case 'category-not-public':
          resolutions.push({ kind: 'category-not-public', categoryId: req.categoryId });
          break;
        case 'unpublish-will-hide-children':
          resolutions.push({ kind: 'unpublish-will-hide-children', entityType: req.entityType, entityId: req.entityId });
          break;
      }
    }
    return resolutions;
  }, [requirements, slugValue]);

  const handleSubmit = useCallback(() => {
    doExecute(buildResolutions());
  }, [doExecute, buildResolutions]);

  const handleCancel = useCallback(() => {
    resetState();
    onClearIntent();
  }, [resetState, onClearIntent]);

  const toggleCollection = useCallback((id: number) => {
    setAcknowledgedCollections(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);

  const toggleCategory = useCallback((id: number) => {
    setAcknowledgedCategories(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);

  const toggleUnpublish = useCallback((key: string) => {
    setAcknowledgedUnpublish(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }, []);

  if (!showModal || !intent) return null;

  const isPublish = intent.action === 'publish';
  const title = isPublish ? 'Publish' : 'Make Private';

  return (
    <div className="publish-resolver__overlay" onClick={handleCancel}>
      <div className="publish-resolver" onClick={e => e.stopPropagation()}>
        <div className="publish-resolver__header">
          <h2 className="publish-resolver__title">{title}</h2>
        </div>

        <div className="publish-resolver__body">
          {error && <div className="publish-resolver__error" role="alert">{error}</div>}

          {requirements.map((req, i) => {
            switch (req.kind) {
              case 'workspace-slug-required':
                return (
                  <div key={i} className="publish-resolver__slug-group">
                    <p className="publish-resolver__slug-label">
                      Your workspace needs a public gallery URL before publishing.
                    </p>
                    <label htmlFor="publish-slug-input" className="publish-resolver__slug-label">Gallery URL</label>
                    <input
                      id="publish-slug-input"
                      type="text"
                      className="publish-resolver__slug-input"
                      value={slugValue}
                      onChange={e => setSlugValue(e.target.value)}
                      placeholder="my-collection"
                      maxLength={50}
                    />
                    <p className="publish-resolver__slug-preview">/public/{slugValue}</p>
                  </div>
                );

              case 'collection-not-public':
                return (
                  <div key={i} className="publish-resolver__requirement">
                    <input
                      type="checkbox"
                      id={`ack-col-${req.collectionId}`}
                      checked={acknowledgedCollections.has(req.collectionId)}
                      onChange={() => toggleCollection(req.collectionId)}
                    />
                    <label htmlFor={`ack-col-${req.collectionId}`}>
                      Collection &apos;{req.collectionName}&apos; will be made public
                    </label>
                  </div>
                );

              case 'category-not-public':
                return (
                  <div key={i} className="publish-resolver__requirement">
                    <input
                      type="checkbox"
                      id={`ack-cat-${req.categoryId}`}
                      checked={acknowledgedCategories.has(req.categoryId)}
                      onChange={() => toggleCategory(req.categoryId)}
                    />
                    <label htmlFor={`ack-cat-${req.categoryId}`}>
                      Category &apos;{req.categoryName}&apos; will be made public
                    </label>
                  </div>
                );

              case 'unpublish-will-hide-children': {
                const key = `${req.entityType}-${req.entityId}`;
                return (
                  <div key={i}>
                    <div className="publish-resolver__impact">
                      Making &apos;{req.entityName}&apos; private will hide{' '}
                      {req.affectedPublicItems} {req.affectedPublicItems === 1 ? 'item' : 'items'}
                      {req.affectedPublicCategories > 0 && (
                        <> and {req.affectedPublicCategories} {req.affectedPublicCategories === 1 ? 'category' : 'categories'}</>
                      )}
                      {' '}from your public gallery. They will reappear if you make this {req.entityType} public again.
                    </div>
                    <div className="publish-resolver__requirement">
                      <input
                        type="checkbox"
                        id={`ack-unpub-${key}`}
                        checked={acknowledgedUnpublish.has(key)}
                        onChange={() => toggleUnpublish(key)}
                      />
                      <label htmlFor={`ack-unpub-${key}`}>I understand</label>
                    </div>
                  </div>
                );
              }

              default:
                return null;
            }
          })}
        </div>

        <div className="publish-resolver__footer">
          <button
            type="button"
            className="modal__button modal__button--secondary"
            onClick={handleCancel}
          >
            Cancel
          </button>
          <button
            type="button"
            className="modal__button modal__button--primary"
            onClick={handleSubmit}
            disabled={!allResolved() || loading}
          >
            {loading ? 'Processing...' : isPublish ? 'Publish' : 'Make Private'}
          </button>
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Run tests**

Run: `cd frontend && npx vitest run tests/PublishResolver.test.tsx`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/common/PublishResolver.tsx frontend/tests/PublishResolver.test.tsx frontend/src/styles/components/publish-resolver.css
git commit -m "feat: add PublishResolver unified publish/unpublish component"
```

---

### Task 11: Integrate PublishResolver into App and Update Consuming Components

Wire up the `PublishProvider` and `PublishResolver` at the app level. Update all consuming components to use `usePublish()` instead of managing their own publish flows.

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/components/item/ItemCard.tsx`
- Modify: `frontend/src/components/item/ItemList.tsx`
- Modify: `frontend/src/components/category/CategoryManagerModal.tsx`
- Modify: `frontend/src/components/category/CategoryManagerForm.tsx`
- Modify: `frontend/src/components/collection/CollectionList.tsx`
- Modify: `frontend/src/views/CategoryView.tsx`

- [ ] **Step 1: Update App.tsx**

In `frontend/src/App.tsx`, add the `PublishProvider` wrapper and `PublishResolver` component.

Add imports:
```typescript
import { PublishProvider } from './contexts/PublishContext';
import { usePublish } from './contexts/usePublish';
import { PublishResolver } from './components/common/PublishResolver';
import { useData } from './contexts/useData';
```

Wrap the app contents in `<PublishProvider>` and add `<PublishResolver>` inside the provider. The `PublishResolver` needs access to `usePublish()`, so create an inner component:

```typescript
function AppContent() {
  // ... existing App component content ...
  const { pendingIntent, clearIntent } = usePublish();
  const { loadCollections, loadCategoriesForCollection, currentCollection } = useData();

  const handlePublishComplete = useCallback(async () => {
    await loadCollections();
    if (currentCollection) {
      await loadCategoriesForCollection(currentCollection.collectionId);
    }
  }, [loadCollections, loadCategoriesForCollection, currentCollection]);

  return (
    <>
      {/* existing JSX */}
      <PublishResolver
        intent={pendingIntent}
        onClearIntent={clearIntent}
        onComplete={handlePublishComplete}
      />
    </>
  );
}

function App() {
  return (
    <PublishProvider>
      <AppContent />
    </PublishProvider>
  );
}
```

Note: The exact integration depends on the current App.tsx structure. The `PublishProvider` must wrap everything that uses `usePublish()`, so it goes at the outermost level within App.

- [ ] **Step 2: Update ItemCard**

In `frontend/src/components/item/ItemCard.tsx`:

Replace the publish handlers with `usePublish()`:

```typescript
import { usePublish } from '../../contexts/usePublish';

// Inside the component:
const { requestPublish, requestUnpublish } = usePublish();

// Replace handlePublish:
function handlePublish() {
  if (item.id === null) return;
  requestPublish([{ type: 'item', id: item.id }]);
}

// Replace handleUnpublish:
function handleUnpublish() {
  if (item.id === null) return;
  requestUnpublish([{ type: 'item', id: item.id }]);
}
```

Remove: `handleSlugConfirm`, `showSlugSetup` state, `SlugSetupModal` render, imports of `publishItem`/`unpublishItem` from DataContext, imports of toast utils, `SlugSetupModal`.

- [ ] **Step 3: Update ItemList**

In `frontend/src/components/item/ItemList.tsx`:

Replace bulk publish handlers:

```typescript
import { usePublish } from '../../contexts/usePublish';

const { requestPublish, requestUnpublish } = usePublish();

function handleBulkPublish() {
  const entities = Array.from(selectedItems).map(id => ({ type: 'item' as const, id }));
  requestPublish(entities);
  handleCancelSelection();
}

function handleBulkUnpublish() {
  const entities = Array.from(selectedItems).map(id => ({ type: 'item' as const, id }));
  requestUnpublish(entities);
  handleCancelSelection();
}
```

Remove: imports of `bulkPublishItems`/`bulkUnpublishItems` from DataContext, toast utils.

- [ ] **Step 4: Update CategoryManagerModal**

In `frontend/src/components/category/CategoryManagerModal.tsx`:

Replace all publish/unpublish handlers:

```typescript
import { usePublish } from '../../contexts/usePublish';

const { requestPublish, requestUnpublish } = usePublish();

const handlePublish = useCallback((category: Category) => {
  requestPublish([{ type: 'category', id: category.categoryId }]);
}, [requestPublish]);

const handleUnpublish = useCallback((category: Category) => {
  requestUnpublish([{ type: 'category', id: category.categoryId }]);
}, [requestUnpublish]);
```

Remove: `publishTarget`/`unpublishTarget`/`unpublishPreview`/`showSlugSetup` state, `handlePublishConfirm`/`handlePublishCancel`/`handleUnpublishConfirm`/`handleUnpublishCancel`/`handleSlugConfirm`/`handleSlugCancel` handlers, `PublishConfirmModal`/`UnpublishConfirmModal`/`SlugSetupModal` renders and imports, `workspacesApi` import, `refetchUser` from `useUser`.

- [ ] **Step 5: Update CategoryManagerForm**

In `frontend/src/components/category/CategoryManagerForm.tsx`:

The publish/unpublish buttons in the visibility section now call `onPublish`/`onUnpublish` which are passed from CategoryManagerModal. These callbacks now use `usePublish` — no changes needed to the form itself since it already delegates via props.

Verify the `onPublish` and `onUnpublish` props are still being used correctly.

- [ ] **Step 6: Update CollectionList**

In `frontend/src/components/collection/CollectionList.tsx`:

```typescript
import { usePublish } from '../../contexts/usePublish';

const { requestPublish, requestUnpublish } = usePublish();

function handlePublishClick(collection: Collection) {
  requestPublish([{ type: 'collection', id: collection.collectionId }]);
}

function handleUnpublishClick(collection: Collection) {
  requestUnpublish([{ type: 'collection', id: collection.collectionId }]);
}
```

Remove: `publishTarget`/`unpublishTarget`/`unpublishPreview`/`showSlugSetup` state, confirm handlers, modal renders and imports.

- [ ] **Step 7: Update CategoryView**

In `frontend/src/views/CategoryView.tsx`:

```typescript
import { usePublish } from '../contexts/usePublish';

const { requestPublish, requestUnpublish } = usePublish();

function handleCollectionPublishClick() {
  if (!currentCollection) return;
  requestPublish([{ type: 'collection', id: currentCollection.collectionId }]);
}

function handleCollectionUnpublishClick() {
  if (!currentCollection) return;
  requestUnpublish([{ type: 'collection', id: currentCollection.collectionId }]);
}
```

Remove: `collectionPublishTarget`/`collectionUnpublishPreview`/`showCollectionSlugSetup` state, confirm handlers, modal renders.

- [ ] **Step 8: Run all frontend tests**

Run: `cd frontend && npx vitest run`
Expected: Existing tests will need updates (next task). Note which tests fail.

- [ ] **Step 9: Commit**

```bash
git add frontend/src/App.tsx frontend/src/components/item/ItemCard.tsx frontend/src/components/item/ItemList.tsx frontend/src/components/category/CategoryManagerModal.tsx frontend/src/components/collection/CollectionList.tsx frontend/src/views/CategoryView.tsx
git commit -m "refactor: integrate PublishResolver and update all consuming components"
```

---

### Task 12: Frontend Cleanup — Remove Old Files, Update Tests, Update DataContext

Delete old publish infrastructure. Update existing tests to use the new patterns. Remove publish methods from DataContext.

**Files:**
- Delete: `frontend/src/api/publish.ts`
- Delete: `frontend/src/components/common/PublishConfirmModal.tsx`
- Delete: `frontend/src/components/common/UnpublishConfirmModal.tsx`
- Delete: `frontend/src/components/common/SlugSetupModal.tsx`
- Delete: `frontend/src/utils/publishToastUtils.ts`
- Delete: `frontend/tests/PublishConfirmModal.test.tsx`
- Delete: `frontend/tests/UnpublishConfirmModal.test.tsx`
- Delete: `frontend/tests/SlugSetupModal.test.tsx`
- Delete: `frontend/tests/api/publish.test.ts`
- Modify: `frontend/src/contexts/DataContext.tsx` — remove all publish methods
- Modify: `frontend/tests/ItemCard.test.tsx` — update publish tests
- Modify: `frontend/tests/ItemList.test.tsx` — update bulk publish tests
- Modify: `frontend/tests/CategoryManagerModal.test.tsx` — update publish tests
- Modify: `frontend/tests/mocks/DataContext.mock.ts` — remove publish mocks

- [ ] **Step 1: Delete old files**

Delete:
- `frontend/src/api/publish.ts`
- `frontend/src/components/common/PublishConfirmModal.tsx`
- `frontend/src/components/common/UnpublishConfirmModal.tsx`
- `frontend/src/components/common/SlugSetupModal.tsx`
- `frontend/src/utils/publishToastUtils.ts`
- `frontend/tests/PublishConfirmModal.test.tsx`
- `frontend/tests/UnpublishConfirmModal.test.tsx`
- `frontend/tests/SlugSetupModal.test.tsx`
- `frontend/tests/api/publish.test.ts`

- [ ] **Step 2: Remove publish methods from DataContext**

In `frontend/src/contexts/DataContext.tsx`:

Remove from the interface: `publishItem`, `unpublishItem`, `publishCategory`, `unpublishCategory`, `publishCollection`, `unpublishCollection`, `bulkPublishItems`, `bulkUnpublishItems`, `getUnpublishCategoryPreview`, `getUnpublishCollectionPreview`.

Remove the corresponding `useCallback` implementations.

Remove the `publishApi` import.

Remove these from the context value object.

- [ ] **Step 3: Update DataContext mock**

In `frontend/tests/mocks/DataContext.mock.ts`:

Remove all publish-related mock methods: `publishItem`, `unpublishItem`, `publishCategory`, `unpublishCategory`, `publishCollection`, `unpublishCollection`, `bulkPublish`, `bulkUnpublish`, `getUnpublishCategoryPreview`, `getUnpublishCollectionPreview`.

- [ ] **Step 4: Update ItemCard tests**

In `frontend/tests/ItemCard.test.tsx`:

Replace publish integration tests to verify `usePublish` is called:

```typescript
const mockRequestPublish = vi.fn();
const mockRequestUnpublish = vi.fn();

vi.mock('../../src/contexts/usePublish', () => ({
  usePublish: () => ({
    requestPublish: mockRequestPublish,
    requestUnpublish: mockRequestUnpublish,
  }),
}));

it('should call requestPublish when clicking Publish button', async () => {
  const user = userEvent.setup();
  render(<ItemCard {...defaultProps} item={privateItem} />);
  await user.click(screen.getByText('Publish'));
  expect(mockRequestPublish).toHaveBeenCalledWith([{ type: 'item', id: 1 }]);
});

it('should call requestUnpublish when clicking Public badge', async () => {
  const user = userEvent.setup();
  render(<ItemCard {...defaultProps} item={publicItem} />);
  await user.click(screen.getByText('Unpublish'));
  expect(mockRequestUnpublish).toHaveBeenCalledWith([{ type: 'item', id: 1 }]);
});
```

Remove tests for `SlugSetupModal` showing up, `publishItem` being called, etc.

- [ ] **Step 5: Update CategoryManagerModal tests**

In `frontend/tests/CategoryManagerModal.test.tsx`:

Replace publish test sections. Instead of testing `publishCategory` calls, `PublishConfirmModal` rendering, and `SlugSetupModal`, test that `requestPublish`/`requestUnpublish` are called with correct entity refs:

```typescript
const mockRequestPublish = vi.fn();
const mockRequestUnpublish = vi.fn();

vi.mock('../../src/contexts/usePublish', () => ({
  usePublish: () => ({
    requestPublish: mockRequestPublish,
    requestUnpublish: mockRequestUnpublish,
  }),
}));

it('should call requestPublish when publish button is clicked', async () => {
  // Navigate to edit view, click publish
  expect(mockRequestPublish).toHaveBeenCalledWith([{ type: 'category', id: expectedId }]);
});

it('should call requestUnpublish when unpublish button is clicked', async () => {
  expect(mockRequestUnpublish).toHaveBeenCalledWith([{ type: 'category', id: expectedId }]);
});
```

Remove all tests related to `PublishConfirmModal`, `UnpublishConfirmModal`, `SlugSetupModal`, `mockPublishCategory`, `mockUnpublishCategory`, `mockGetUnpublishCategoryPreview`.

- [ ] **Step 6: Update remaining test files**

Update any remaining test files (`ItemList.test.tsx`, `CollectionList.test.tsx`, `CategoryView.test.tsx`) with the same pattern — mock `usePublish` and verify `requestPublish`/`requestUnpublish` calls instead of testing DataContext publish methods.

- [ ] **Step 7: Run all tests**

Run: `cd frontend && npx vitest run`
Expected: All tests PASS

Run: `cd frontend && npm run build`
Expected: Build succeeded

Run: `cd frontend && npm run lint`
Expected: No errors

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "refactor: remove old publish infrastructure, update all tests for centralized PublishResolver"
```

---

### Task 13: End-to-End Verification

Run all tests across both backend and frontend to verify the complete migration.

**Files:** None (verification only)

- [ ] **Step 1: Run all backend tests**

Run: `dotnet test backend/tests/backend.tests`
Expected: All tests PASS

- [ ] **Step 2: Run all frontend tests**

Run: `cd frontend && npx vitest run`
Expected: All tests PASS

- [ ] **Step 3: Verify frontend builds**

Run: `cd frontend && npm run build`
Expected: Build succeeded

- [ ] **Step 4: Run frontend lint**

Run: `cd frontend && npm run lint`
Expected: No errors

- [ ] **Step 5: Commit (if any fixes were needed)**

Only if fixes were required in previous steps.
