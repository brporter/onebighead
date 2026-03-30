# Publish Flow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 4-level visibility cascade with a publish-oriented UX where users one-click publish items to their public gallery with automatic parent promotion.

**Architecture:** Simplify the Visibility enum to two states (Public/Private), add dedicated publish/unpublish endpoints that handle parent auto-promotion, and build new frontend components for publish actions, visibility filtering, and bulk operations. The backend VisibilityService is rewritten to support publish with auto-promotion and unpublish with intent preservation.

**Tech Stack:** .NET 10 (C#), EF Core, xUnit, React 19, TypeScript, Vite, Vitest

**Spec:** `docs/superpowers/specs/2026-03-24-publish-flow-design.md`

---

## File Structure

### Backend — New Files
- `backend/src/backend/DTOs/PublishRequests.cs` — Request/response DTOs for all publish/unpublish endpoints
- `backend/src/backend/Controllers/PublishController.cs` — All publish/unpublish/preview endpoints
- `backend/src/backend/Migrations/{timestamp}_SimplifyVisibility.cs` — Data migration (auto-generated)
- `backend/tests/backend.tests/Services/PublishVisibilityServiceTests.cs` — Tests for new publish/unpublish service logic
- `backend/tests/backend.tests/Controllers/PublishControllerTests.cs` — Tests for publish endpoints

### Backend — Modified Files
- `backend/src/backend/Models/Visibility.cs` — Remove `Default` enum value
- `backend/src/backend/Models/Workspace.cs` — Remove `IsPublicAccessEnabled`
- `backend/src/backend/Services/IVisibilityService.cs` — Add publish/unpublish method signatures
- `backend/src/backend/Services/VisibilityService.cs` — Rewrite: add publish/unpublish, simplify compute
- `backend/src/backend/Controllers/WorkspacesController.cs` — Remove `UpdatePublicAccessAsync` endpoint, update slug handling
- `backend/src/backend/Controllers/ItemsController.cs` — Remove visibility from create/update
- `backend/src/backend/Controllers/CategoriesController.cs` — Remove visibility from create/update
- `backend/src/backend/Controllers/CollectionsController.cs` — Remove visibility from create/update
- `backend/src/backend/Controllers/PublicController.cs` — Remove `IsPublicAccessEnabled` check, use slug-only
- `backend/src/backend/Data/WorkspaceRepository.cs` — Update `GetBySlugAsync` to not check `IsPublicAccessEnabled`
- `backend/src/backend/Data/ApplicationDbContext.cs` — Update model configuration if needed
- `backend/src/backend/DTOs/UpdateWorkspacePublicAccessRequest.cs` — Remove (delete file)
- `backend/src/backend/DTOs/UpdateWorkspacePublicAccessResponse.cs` — Remove (delete file)
- `backend/src/backend/DTOs/CategoryRequests.cs` — Remove visibility from create/update requests
- `backend/src/backend/DTOs/CollectionRequests.cs` — Remove visibility from create/update requests
- `backend/tests/backend.tests/Services/VisibilityServiceTests.cs` — Update for two-state model

### Frontend — New Files
- `frontend/src/api/publish.ts` — API client for publish/unpublish endpoints
- `frontend/src/components/common/PublishButton.tsx` — One-click publish button (green, up-arrow)
- `frontend/src/components/common/PublicBadge.tsx` — Public status badge (blue, eye) with hover-to-unpublish (red, crossed-eye)
- `frontend/src/components/common/VisibilityFilter.tsx` — All/Public/Private filter bar
- `frontend/src/components/common/BulkActionBar.tsx` — Selection bar with publish/unpublish/cancel
- `frontend/src/components/common/PublishConfirmModal.tsx` — Category/collection publish prompt
- `frontend/src/components/common/UnpublishConfirmModal.tsx` — Unpublish confirmation with affected counts
- `frontend/src/components/common/SlugSetupModal.tsx` — First-publish slug creation modal
- `frontend/src/styles/components/publish.css` — Styles for all publish-related components
- `frontend/src/styles/components/visibility-filter.css` — Filter bar and animation styles
- `frontend/src/__tests__/api/publish.test.ts` — Tests for publish API module
- `frontend/src/__tests__/components/PublishButton.test.tsx` — Tests for publish button
- `frontend/src/__tests__/components/PublicBadge.test.tsx` — Tests for public badge
- `frontend/src/__tests__/components/VisibilityFilter.test.tsx` — Tests for filter bar
- `frontend/src/__tests__/components/BulkActionBar.test.tsx` — Tests for bulk actions
- `frontend/src/__tests__/components/PublishConfirmModal.test.tsx` — Tests for publish confirm modal
- `frontend/src/__tests__/components/UnpublishConfirmModal.test.tsx` — Tests for unpublish confirm modal
- `frontend/src/__tests__/components/SlugSetupModal.test.tsx` — Tests for slug setup modal

### Frontend — Modified Files
- `frontend/src/utils/types.ts` — Remove `Default` from Visibility enum, add publish response types
- `frontend/src/api/collections.ts` — Remove visibility from create/update requests
- `frontend/src/api/categories.ts` — Remove visibility from create/update requests
- `frontend/src/api/items.ts` — Remove visibility from create/update requests (if present)
- `frontend/src/api/workspaces.ts` — Remove `UpdatePublicAccessRequest`/`Response`, simplify slug handling
- `frontend/src/contexts/DataContext.tsx` — Remove visibility from add/update methods, add publish/unpublish methods
- `frontend/src/components/item/ItemCard.tsx` — Add PublicBadge and PublishButton
- `frontend/src/components/item/ItemList.tsx` — Add VisibilityFilter, bulk selection, BulkActionBar
- `frontend/src/components/workspace/WorkspaceEditModal.tsx` — Remove `IsPublicAccessEnabled` checkbox, update slug section
- `frontend/src/components/common/VisibilityToggle.tsx` — Delete (replaced by publish/unpublish components)
- `frontend/src/App.tsx` — Add Public Gallery link to header

---

## Task Sequence

### Task 1: Simplify Visibility Enum (Backend)

**Files:**
- Modify: `backend/src/backend/Models/Visibility.cs`
- Modify: `backend/tests/backend.tests/Services/VisibilityServiceTests.cs`

- [ ] **Step 1: Read current Visibility.cs and VisibilityServiceTests.cs**

Read both files to understand current state before making changes.

- [ ] **Step 2: Update VisibilityServiceTests to use two-state model**

Update all tests that reference `Visibility.Default` to use `Visibility.Private` or `Visibility.Public` as appropriate. Remove tests specifically about Default/inheritance behavior. Add tests for the simplified two-state model:

```csharp
[Fact]
[Trait("Category", "Unit")]
public void Category_Public_With_Public_Collection_Is_EffectivelyPublic()
{
    var collection = new Collection { Visibility = Visibility.Public };
    var category = new Category { Visibility = Visibility.Public };
    var service = new VisibilityService();
    service.ComputeEffectiveVisibility(category, collection, new List<Category>());
    Assert.True(category.EffectiveIsPublic);
}

[Fact]
[Trait("Category", "Unit")]
public void Category_Public_With_Private_Collection_Is_Not_EffectivelyPublic()
{
    var collection = new Collection { Visibility = Visibility.Private };
    var category = new Category { Visibility = Visibility.Public };
    var service = new VisibilityService();
    service.ComputeEffectiveVisibility(category, collection, new List<Category>());
    Assert.False(category.EffectiveIsPublic);
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `dotnet test backend/tests/backend.tests --filter "Category=Unit"`
Expected: Tests that relied on `Default` should fail.

- [ ] **Step 4: Remove Default from Visibility enum**

In `backend/src/backend/Models/Visibility.cs`, remove the `Default` value. The enum becomes:

```csharp
using System.Text.Json.Serialization;

namespace backend.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum Visibility
{
    Private = 1,
    Public = 2,
}
```

- [ ] **Step 5: Fix compilation errors**

Update `VisibilityService.cs` to remove all `Visibility.Default` handling. Simplify the compute methods — without `Default`, visibility is simply: entity is effectively public when own `Visibility == Public` AND all ancestors are `Public`.

Update model defaults in `Item.cs`, `Category.cs` to default to `Visibility.Private` instead of `Visibility.Default`.

- [ ] **Step 6: Run tests to verify they pass**

Run: `dotnet test backend/tests/backend.tests --filter "Category=Unit"`
Expected: All updated tests pass.

- [ ] **Step 7: Commit**

```bash
git add backend/src/backend/Models/Visibility.cs backend/src/backend/Services/VisibilityService.cs backend/src/backend/Models/Item.cs backend/src/backend/Models/Category.cs backend/tests/backend.tests/Services/VisibilityServiceTests.cs
git commit -m "feat: simplify Visibility enum to Public/Private only"
```

---

### Task 2: Remove IsPublicAccessEnabled from Workspace (Backend)

**Files:**
- Modify: `backend/src/backend/Models/Workspace.cs`
- Modify: `backend/src/backend/Data/WorkspaceRepository.cs`
- Modify: `backend/src/backend/Controllers/PublicController.cs`
- Delete: `backend/src/backend/DTOs/UpdateWorkspacePublicAccessRequest.cs`
- Delete: `backend/src/backend/DTOs/UpdateWorkspacePublicAccessResponse.cs`
- Modify: `backend/src/backend/Controllers/WorkspacesController.cs`

- [ ] **Step 1: Read all affected files**

Read Workspace.cs, WorkspaceRepository.cs, PublicController.cs, WorkspacesController.cs (especially the public access endpoints around lines 620-697), and the two DTO files to be deleted.

- [ ] **Step 2: Update existing tests that reference IsPublicAccessEnabled**

Find and update all tests that set or check `IsPublicAccessEnabled`. The new logic is: workspace has a slug = public access is possible.

Run: search for `IsPublicAccessEnabled` across all test files.

- [ ] **Step 3: Run tests to verify they fail**

Run: `dotnet test backend/tests/backend.tests`
Expected: Tests referencing `IsPublicAccessEnabled` should fail.

- [ ] **Step 4: Remove IsPublicAccessEnabled from Workspace model**

In `Workspace.cs`, remove the `IsPublicAccessEnabled` property. Keep `Slug`.

- [ ] **Step 5: Update WorkspaceRepository.GetBySlugAsync**

In `WorkspaceRepository.cs` (line 43-48), remove the `IsPublicAccessEnabled` check. The method should return any non-deleted workspace with a matching slug:

```csharp
public async Task<Workspace?> GetBySlugAsync(string slug)
{
    return await _context.Workspaces
        .AsNoTracking()
        .FirstOrDefaultAsync(w => w.Slug == slug && !w.IsDeleted);
}
```

- [ ] **Step 6: Update PublicController**

In `PublicController.cs`, remove any checks for `IsPublicAccessEnabled`. The check is now: does the workspace have a slug? (which `GetBySlugAsync` already handles by returning null if no match).

- [ ] **Step 7: Remove public access endpoints from WorkspacesController**

Remove the `UpdatePublicAccessAsync` and `GetPublicAccessAsync` endpoints (lines ~620-697). Slug management will be handled through the existing workspace update endpoint.

Ensure the workspace update endpoint can set/clear the slug field.

- [ ] **Step 8: Delete the public access DTOs**

Delete `UpdateWorkspacePublicAccessRequest.cs` and `UpdateWorkspacePublicAccessResponse.cs`.

- [ ] **Step 9: Run all tests**

Run: `dotnet test backend/tests/backend.tests`
Expected: All tests pass.

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "feat: remove IsPublicAccessEnabled, use slug presence for public access"
```

---

### Task 3: Create Publish/Unpublish DTOs (Backend)

**Files:**
- Create: `backend/src/backend/DTOs/PublishRequests.cs`

- [ ] **Step 1: Create the DTOs file**

```csharp
namespace backend.DTOs;

// === Requests ===

public class PublishCategoryRequest
{
    public bool IncludeChildren { get; set; }
}

public class PublishCollectionRequest
{
    public bool IncludeChildren { get; set; }
}

public class BulkPublishRequest
{
    public required List<int> ItemIds { get; set; }
}

public class BulkUnpublishRequest
{
    public required List<int> ItemIds { get; set; }
}

// === Responses ===

public class PublishedEntityInfo
{
    public required string Type { get; set; }
    public int Id { get; set; }
    public required string Name { get; set; }
}

public class PublishResponse
{
    public required PublishedEntityInfo Published { get; set; }
    public List<PublishedEntityInfo> Promoted { get; set; } = new();
    public int ChildrenPublished { get; set; }
    public bool RequiresSlugSetup { get; set; }
}

public class BulkPublishResponse
{
    public int PublishedCount { get; set; }
    public List<PublishedEntityInfo> Promoted { get; set; } = new();
    public bool RequiresSlugSetup { get; set; }
}

public class UnpublishResponse
{
    public required PublishedEntityInfo Unpublished { get; set; }
    public int AffectedPublicItems { get; set; }
    public int AffectedPublicCategories { get; set; }
}

public class BulkUnpublishResponse
{
    public int UnpublishedCount { get; set; }
}

public class UnpublishPreviewResponse
{
    public int AffectedPublicItems { get; set; }
    public int AffectedPublicCategories { get; set; }
}
```

- [ ] **Step 2: Run tests to make sure nothing broke**

Run: `dotnet test backend/tests/backend.tests`
Expected: All pass (new file, no changes to existing code).

- [ ] **Step 3: Commit**

```bash
git add backend/src/backend/DTOs/PublishRequests.cs
git commit -m "feat: add publish/unpublish request and response DTOs"
```

---

### Task 4: Add Publish/Unpublish Methods to VisibilityService (Backend)

**Files:**
- Modify: `backend/src/backend/Services/IVisibilityService.cs`
- Modify: `backend/src/backend/Services/VisibilityService.cs`
- Create: `backend/tests/backend.tests/Services/PublishVisibilityServiceTests.cs`

- [ ] **Step 1: Write failing tests for PublishAsync**

Create `PublishVisibilityServiceTests.cs` with tests:

```csharp
using backend.Models;
using backend.Services;
using Xunit;

namespace backend.tests.Services;

public class PublishVisibilityServiceTests
{
    private readonly VisibilityService _service = new();

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishItem_SetsItemPublic()
    {
        var item = new Item { Visibility = Visibility.Private };
        // PublishItem should exist on VisibilityService
        var result = _service.PublishItem(item, collection: new Collection { Visibility = Visibility.Public }, category: null);
        Assert.Equal(Visibility.Public, item.Visibility);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishItem_PromotesPrivateCategory()
    {
        var collection = new Collection { Id = 1, Visibility = Visibility.Public };
        var category = new Category { Id = 5, Name = "Vintage Watches", Visibility = Visibility.Private };
        var item = new Item { Visibility = Visibility.Private, CategoryId = 5 };

        var result = _service.PublishItem(item, collection, category);

        Assert.Equal(Visibility.Public, item.Visibility);
        Assert.Equal(Visibility.Public, category.Visibility);
        Assert.Single(result.Promoted);
        Assert.Equal("category", result.Promoted[0].Type);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishItem_PromotesPrivateCategoryAndCollection()
    {
        var collection = new Collection { Id = 1, Name = "My Collection", Visibility = Visibility.Private };
        var category = new Category { Id = 5, Name = "Vintage Watches", Visibility = Visibility.Private };
        var item = new Item { Visibility = Visibility.Private, CategoryId = 5 };

        var result = _service.PublishItem(item, collection, category);

        Assert.Equal(Visibility.Public, item.Visibility);
        Assert.Equal(Visibility.Public, category.Visibility);
        Assert.Equal(Visibility.Public, collection.Visibility);
        Assert.Equal(2, result.Promoted.Count);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishItem_NoCategory_PromotesCollection()
    {
        var collection = new Collection { Id = 1, Name = "My Collection", Visibility = Visibility.Private };
        var item = new Item { Visibility = Visibility.Private };

        var result = _service.PublishItem(item, collection, category: null);

        Assert.Equal(Visibility.Public, item.Visibility);
        Assert.Equal(Visibility.Public, collection.Visibility);
        Assert.Single(result.Promoted);
        Assert.Equal("collection", result.Promoted[0].Type);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishCategory_WithChildren_PublishesAllItems()
    {
        var collection = new Collection { Id = 1, Visibility = Visibility.Public };
        var category = new Category { Id = 5, Name = "Watches", Visibility = Visibility.Private };
        var items = new List<Item>
        {
            new() { Id = 1, Visibility = Visibility.Private, CategoryId = 5 },
            new() { Id = 2, Visibility = Visibility.Private, CategoryId = 5 },
            new() { Id = 3, Visibility = Visibility.Public, CategoryId = 5 },
        };

        var result = _service.PublishCategory(category, collection, items, allCategories: new List<Category> { category }, includeChildren: true);

        Assert.Equal(Visibility.Public, category.Visibility);
        Assert.All(items, i => Assert.Equal(Visibility.Public, i.Visibility));
        Assert.Equal(2, result.ChildrenPublished); // only the 2 that were private
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishCategory_WithChildren_PublishesSubcategoriesAndTheirItems()
    {
        var collection = new Collection { Id = 1, Visibility = Visibility.Public };
        var parentCategory = new Category { Id = 5, Name = "Watches", Visibility = Visibility.Private };
        var childCategory = new Category { Id = 6, Name = "Dive Watches", Visibility = Visibility.Private, ParentCategoryId = 5 };
        var allCategories = new List<Category> { parentCategory, childCategory };
        var items = new List<Item>
        {
            new() { Id = 1, Visibility = Visibility.Private, CategoryId = 5 },
            new() { Id = 2, Visibility = Visibility.Private, CategoryId = 6 },
        };

        var result = _service.PublishCategory(parentCategory, collection, items, allCategories, includeChildren: true);

        Assert.Equal(Visibility.Public, parentCategory.Visibility);
        Assert.Equal(Visibility.Public, childCategory.Visibility);
        Assert.All(items, i => Assert.Equal(Visibility.Public, i.Visibility));
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void PublishCategory_WithoutChildren_OnlyPublishesCategory()
    {
        var collection = new Collection { Id = 1, Visibility = Visibility.Public };
        var category = new Category { Id = 5, Name = "Watches", Visibility = Visibility.Private };
        var items = new List<Item>
        {
            new() { Id = 1, Visibility = Visibility.Private, CategoryId = 5 },
        };

        var result = _service.PublishCategory(category, collection, items, allCategories: new List<Category> { category }, includeChildren: false);

        Assert.Equal(Visibility.Public, category.Visibility);
        Assert.Equal(Visibility.Private, items[0].Visibility); // item untouched
        Assert.Equal(0, result.ChildrenPublished);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void UnpublishCategory_DoesNotCascadeToChildren()
    {
        var category = new Category { Id = 5, Name = "Watches", Visibility = Visibility.Public };
        var items = new List<Item>
        {
            new() { Id = 1, Visibility = Visibility.Public, CategoryId = 5 },
            new() { Id = 2, Visibility = Visibility.Public, CategoryId = 5 },
        };

        _service.UnpublishEntity(category);

        Assert.Equal(Visibility.Private, category.Visibility);
        Assert.All(items, i => Assert.Equal(Visibility.Public, i.Visibility)); // items retain intent
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void UnpublishPreview_ReturnsAffectedCounts()
    {
        var collection = new Collection { Id = 1, Visibility = Visibility.Public };
        var category = new Category { Id = 5, Visibility = Visibility.Public };
        var items = new List<Item>
        {
            new() { Id = 1, Visibility = Visibility.Public, CategoryId = 5 },
            new() { Id = 2, Visibility = Visibility.Public, CategoryId = 5 },
            new() { Id = 3, Visibility = Visibility.Private, CategoryId = 5 },
        };

        var preview = _service.GetUnpublishPreview(category, items, new List<Category>(), collection);

        Assert.Equal(2, preview.AffectedPublicItems);
        Assert.Equal(0, preview.AffectedPublicCategories);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void RequiresSlugSetup_WhenWorkspaceHasNoSlug()
    {
        var workspace = new Workspace { Slug = null };
        Assert.True(_service.RequiresSlugSetup(workspace));
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void RequiresSlugSetup_False_WhenWorkspaceHasSlug()
    {
        var workspace = new Workspace { Slug = "my-gallery" };
        Assert.False(_service.RequiresSlugSetup(workspace));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test backend/tests/backend.tests --filter "FullyQualifiedName~PublishVisibilityServiceTests"`
Expected: Compilation failures — methods don't exist yet.

- [ ] **Step 3: Add method signatures to IVisibilityService**

Add the following to `IVisibilityService.cs`:

```csharp
PublishResult PublishItem(Item item, Collection collection, Category? category);
PublishResult PublishCategory(Category category, Collection collection, IEnumerable<Item> categoryItems, IEnumerable<Category> allCategories, bool includeChildren);
PublishResult PublishCollection(Collection collection, IEnumerable<Category> categories, IEnumerable<Item> items, bool includeChildren);
void UnpublishEntity(IVisibilityEntity entity);
UnpublishPreview GetUnpublishPreview(Category category, IEnumerable<Item> items, IEnumerable<Category> childCategories, Collection collection);
UnpublishPreview GetUnpublishPreviewForCollection(Collection collection, IEnumerable<Category> categories, IEnumerable<Item> items);
bool RequiresSlugSetup(Workspace workspace);
```

Note: `PublishResult` and `UnpublishPreview` are simple data classes returned by the service. Define them in the service file or a separate file. `IVisibilityEntity` may need to be an interface on the models, or the method can take the concrete type. Adapt based on the existing pattern — if models don't share an interface, use separate overloads or set `Visibility` directly.

- [ ] **Step 4: Implement the methods in VisibilityService**

Implement each method:

- `PublishItem`: Set item to Public, check category (if present) and promote if Private, check collection and promote if Private. Return list of promoted entities.
- `PublishCategory`: Set category to Public, promote parent categories up the chain, promote collection if needed. If `includeChildren`, set all items to Public and count how many changed.
- `PublishCollection`: Set collection to Public. If `includeChildren`, set all categories and items to Public.
- `UnpublishEntity`: Set entity's Visibility to Private. No cascade.
- `GetUnpublishPreview`: Count items and child categories that are currently effectively public under the given entity.
- `RequiresSlugSetup`: Return `workspace.Slug == null`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `dotnet test backend/tests/backend.tests --filter "FullyQualifiedName~PublishVisibilityServiceTests"`
Expected: All pass.

- [ ] **Step 6: Run all tests**

Run: `dotnet test backend/tests/backend.tests`
Expected: All pass.

- [ ] **Step 7: Commit**

```bash
git add backend/src/backend/Services/IVisibilityService.cs backend/src/backend/Services/VisibilityService.cs backend/tests/backend.tests/Services/PublishVisibilityServiceTests.cs
git commit -m "feat: add publish/unpublish methods to VisibilityService"
```

---

### Task 5: Create PublishController (Backend)

**Files:**
- Create: `backend/src/backend/Controllers/PublishController.cs`
- Create: `backend/tests/backend.tests/Controllers/PublishControllerTests.cs`

- [ ] **Step 1: Write integration tests for publish endpoints**

Create `PublishControllerTests.cs`. Follow the pattern in existing controller tests (check `PublicControllerTests.cs` and `ItemsControllerIntegrationTests.cs` for the test setup pattern). Write tests for:

- `POST /api/workspaces/{id}/items/{itemId}/publish` — publishes item, returns promoted entities
- `POST /api/workspaces/{id}/items/{itemId}/unpublish` — unpublishes item
- `POST /api/workspaces/{id}/categories/{categoryId}/publish` with `includeChildren: true` — publishes category and items
- `POST /api/workspaces/{id}/categories/{categoryId}/publish` with `includeChildren: false` — publishes category only
- `POST /api/workspaces/{id}/categories/{categoryId}/unpublish` — unpublishes category
- `GET /api/workspaces/{id}/categories/{categoryId}/unpublish-preview` — returns affected counts
- `POST /api/workspaces/{id}/collections/{collectionId}/publish` — publishes collection
- `POST /api/workspaces/{id}/collections/{collectionId}/unpublish` — unpublishes collection
- `GET /api/workspaces/{id}/collections/{collectionId}/unpublish-preview` — returns affected counts
- `POST /api/workspaces/{id}/items/bulk-publish` — bulk publishes items
- `POST /api/workspaces/{id}/items/bulk-unpublish` — bulk unpublishes items
- Publish returns `requiresSlugSetup: true` when workspace has no slug

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test backend/tests/backend.tests --filter "FullyQualifiedName~PublishControllerTests"`
Expected: Failures — controller doesn't exist.

- [ ] **Step 3: Create PublishController**

Create `PublishController.cs` inheriting from `ApiControllerBase` (workspace-scoped). Route: `api/workspaces/{workspaceId}`.

Inject `IVisibilityService`, `IItemRepository`, `ICategoryRepository`, `ICollectionRepository`, `IWorkspaceRepository`.

Implement all endpoints:

```csharp
// Item publish/unpublish
[HttpPost("items/{itemId}/publish")]
[HttpPost("items/{itemId}/unpublish")]

// Category publish/unpublish/preview
[HttpPost("categories/{categoryId}/publish")]
[HttpPost("categories/{categoryId}/unpublish")]
[HttpGet("categories/{categoryId}/unpublish-preview")]

// Collection publish/unpublish/preview
[HttpPost("collections/{collectionId}/publish")]
[HttpPost("collections/{collectionId}/unpublish")]
[HttpGet("collections/{collectionId}/unpublish-preview")]

// Bulk operations
[HttpPost("items/bulk-publish")]
[HttpPost("items/bulk-unpublish")]
```

Each endpoint:
1. Gets the entity from the repository
2. Gets related entities (collection, categories, items as needed)
3. Calls the appropriate VisibilityService method
4. Saves changes via repository
5. Returns the appropriate response DTO

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test backend/tests/backend.tests --filter "FullyQualifiedName~PublishControllerTests"`
Expected: All pass.

- [ ] **Step 5: Run all tests**

Run: `dotnet test backend/tests/backend.tests`
Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add backend/src/backend/Controllers/PublishController.cs backend/tests/backend.tests/Controllers/PublishControllerTests.cs
git commit -m "feat: add PublishController with publish/unpublish/preview endpoints"
```

---

### Task 6: Remove Visibility from Create/Update Endpoints (Backend)

**Files:**
- Modify: `backend/src/backend/Controllers/ItemsController.cs`
- Modify: `backend/src/backend/Controllers/CategoriesController.cs`
- Modify: `backend/src/backend/Controllers/CollectionsController.cs`
- Modify: `backend/src/backend/DTOs/CategoryRequests.cs` (or equivalent)
- Modify: `backend/src/backend/DTOs/CollectionRequests.cs` (or equivalent)

- [ ] **Step 1: Read all affected DTOs and controllers**

Read the create/update request DTOs for items, categories, and collections. Identify where `Visibility` is accepted as a request parameter.

- [ ] **Step 2: Update tests that pass visibility in create/update requests**

Find tests that set visibility during creation/updates and remove that field. New items/categories default to their parent's visibility (implemented in the controller logic).

- [ ] **Step 3: Run tests to verify they fail**

Run: `dotnet test backend/tests/backend.tests`
Expected: Some tests may fail due to removed fields.

- [ ] **Step 4: Remove Visibility from request DTOs**

Remove the `Visibility` property from `CreateCategoryRequest`, `UpdateCategoryRequest`, `CreateCollectionRequest`, `UpdateCollectionRequest`, and any item create/update DTOs that include it.

- [ ] **Step 5: Update controller logic for default visibility**

In each create endpoint, set the default visibility based on the parent:

- **Items:** If item's category is public → `Visibility.Public`, else `Visibility.Private`. If no category, use collection's visibility.
- **Categories:** If parent category is public → `Visibility.Public`. If no parent, use collection's visibility.
- **Collections:** Default to `Visibility.Private`.

- [ ] **Step 6: Run all tests**

Run: `dotnet test backend/tests/backend.tests`
Expected: All pass.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: remove visibility from create/update DTOs, default from parent"
```

---

### Task 7: Database Migration (Backend)

**Files:**
- Create: auto-generated migration file

- [ ] **Step 1: Create the migration**

Run from `backend/src/backend`:

```bash
dotnet ef migrations add SimplifyVisibility
```

This should generate a migration that:
- Drops the `IsPublicAccessEnabled` column from `Workspaces`
- Note: The `Visibility` column type doesn't change (still an int), but we need a data migration

- [ ] **Step 2: Edit the migration to resolve Default values**

In the generated migration's `Up` method, add SQL before any schema changes to resolve existing `Default` (0) values:

```csharp
// Resolve Default (0) visibility values
// Items: inherit from category, then collection
migrationBuilder.Sql(@"
    UPDATE i SET i.Visibility =
        CASE
            WHEN c.Visibility = 2 THEN 2  -- Category is Public
            WHEN col.Visibility = 2 THEN 2  -- Collection is Public
            ELSE 1  -- Private
        END
    FROM Items i
    LEFT JOIN Categories c ON i.CategoryId = c.Id
    LEFT JOIN Collections col ON i.CollectionId = col.Id
    WHERE i.Visibility = 0
");

// Categories: inherit from parent category, then collection
migrationBuilder.Sql(@"
    -- First pass: categories with parents
    UPDATE cat SET cat.Visibility =
        CASE
            WHEN parent.Visibility = 2 THEN 2
            ELSE 1
        END
    FROM Categories cat
    INNER JOIN Categories parent ON cat.ParentCategoryId = parent.Id
    WHERE cat.Visibility = 0 AND parent.Visibility != 0
");

migrationBuilder.Sql(@"
    -- Second pass: root categories (no parent)
    UPDATE cat SET cat.Visibility =
        CASE
            WHEN col.Visibility = 2 THEN 2
            ELSE 1
        END
    FROM Categories cat
    INNER JOIN Collections col ON cat.CollectionId = col.Id
    WHERE cat.Visibility = 0 AND cat.ParentCategoryId IS NULL
");

// Handle deeply nested categories with a recursive CTE
migrationBuilder.Sql(@"
    ;WITH ResolvedCategories AS (
        -- Base case: root categories (no parent) inherit from collection
        SELECT cat.Id, cat.CollectionId, cat.ParentCategoryId,
            CASE WHEN col.Visibility = 2 THEN 2 ELSE 1 END AS ResolvedVisibility
        FROM Categories cat
        INNER JOIN Collections col ON cat.CollectionId = col.Id
        WHERE cat.ParentCategoryId IS NULL AND cat.Visibility = 0

        UNION ALL

        -- Recursive case: child categories inherit from resolved parent
        SELECT child.Id, child.CollectionId, child.ParentCategoryId,
            CASE WHEN parent.ResolvedVisibility = 2 THEN 2 ELSE 1 END AS ResolvedVisibility
        FROM Categories child
        INNER JOIN ResolvedCategories parent ON child.ParentCategoryId = parent.Id
        WHERE child.Visibility = 0
    )
    UPDATE cat SET cat.Visibility = rc.ResolvedVisibility
    FROM Categories cat
    INNER JOIN ResolvedCategories rc ON cat.Id = rc.Id
");

// Remaining Default values become Private (safety net)
migrationBuilder.Sql("UPDATE Items SET Visibility = 1 WHERE Visibility = 0");
migrationBuilder.Sql("UPDATE Categories SET Visibility = 1 WHERE Visibility = 0");
```

Then the schema change:

```csharp
migrationBuilder.DropColumn(name: "IsPublicAccessEnabled", table: "Workspaces");
```

- [ ] **Step 3: Test the migration locally**

Reset the local database and verify the migration applies cleanly:

```bash
./scripts/reset-database.sh
```

Then start the backend and verify it runs.

- [ ] **Step 4: Run all tests**

Run: `dotnet test backend/tests/backend.tests`
Expected: All pass.

- [ ] **Step 5: Commit**

```bash
git add backend/src/backend/Migrations/
git commit -m "feat: add migration to simplify visibility and remove IsPublicAccessEnabled"
```

---

### Task 8: Frontend Types and Publish API (Frontend)

**Files:**
- Modify: `frontend/src/utils/types.ts`
- Create: `frontend/src/api/publish.ts`
- Create: `frontend/src/__tests__/api/publish.test.ts`

- [ ] **Step 1: Write tests for publish API module**

Create `frontend/src/__tests__/api/publish.test.ts` with tests for each API function. Mock the HTTP client. Test that correct URLs and payloads are sent.

- [ ] **Step 2: Run tests to verify they fail**

Run: `npm run test:run -- --reporter verbose __tests__/api/publish.test.ts`
Expected: Failures — module doesn't exist.

- [ ] **Step 3: Update Visibility enum in types.ts**

Remove `Default` from the enum:

```typescript
export enum Visibility {
  Private = "Private",
  Public = "Public",
}
```

Add publish response types:

```typescript
export interface PublishedEntityInfo {
  type: string;
  id: number;
  name: string;
}

export interface PublishResponse {
  published: PublishedEntityInfo;
  promoted: PublishedEntityInfo[];
  childrenPublished: number;
  requiresSlugSetup: boolean;
}

export interface BulkPublishResponse {
  publishedCount: number;
  promoted: PublishedEntityInfo[];
  requiresSlugSetup: boolean;
}

export interface UnpublishResponse {
  unpublished: PublishedEntityInfo;
  affectedPublicItems: number;
  affectedPublicCategories: number;
}

export interface BulkUnpublishResponse {
  unpublishedCount: number;
}

export interface UnpublishPreviewResponse {
  affectedPublicItems: number;
  affectedPublicCategories: number;
}
```

- [ ] **Step 4: Create publish API module**

Create `frontend/src/api/publish.ts`:

```typescript
import { client } from './client';
import type {
  PublishResponse,
  BulkPublishResponse,
  UnpublishResponse,
  BulkUnpublishResponse,
  UnpublishPreviewResponse,
} from '../utils/types';

const publishApi = {
  publishItem: (workspaceId: number, itemId: number) =>
    client.post<PublishResponse>(`/api/workspaces/${workspaceId}/items/${itemId}/publish`),

  unpublishItem: (workspaceId: number, itemId: number) =>
    client.post<UnpublishResponse>(`/api/workspaces/${workspaceId}/items/${itemId}/unpublish`),

  publishCategory: (workspaceId: number, categoryId: number, includeChildren: boolean) =>
    client.post<PublishResponse>(`/api/workspaces/${workspaceId}/categories/${categoryId}/publish`, { includeChildren }),

  unpublishCategory: (workspaceId: number, categoryId: number) =>
    client.post<UnpublishResponse>(`/api/workspaces/${workspaceId}/categories/${categoryId}/unpublish`),

  unpublishCategoryPreview: (workspaceId: number, categoryId: number) =>
    client.get<UnpublishPreviewResponse>(`/api/workspaces/${workspaceId}/categories/${categoryId}/unpublish-preview`),

  publishCollection: (workspaceId: number, collectionId: number, includeChildren: boolean) =>
    client.post<PublishResponse>(`/api/workspaces/${workspaceId}/collections/${collectionId}/publish`, { includeChildren }),

  unpublishCollection: (workspaceId: number, collectionId: number) =>
    client.post<UnpublishResponse>(`/api/workspaces/${workspaceId}/collections/${collectionId}/unpublish`),

  unpublishCollectionPreview: (workspaceId: number, collectionId: number) =>
    client.get<UnpublishPreviewResponse>(`/api/workspaces/${workspaceId}/collections/${collectionId}/unpublish-preview`),

  bulkPublish: (workspaceId: number, itemIds: number[]) =>
    client.post<BulkPublishResponse>(`/api/workspaces/${workspaceId}/items/bulk-publish`, { itemIds }),

  bulkUnpublish: (workspaceId: number, itemIds: number[]) =>
    client.post<BulkUnpublishResponse>(`/api/workspaces/${workspaceId}/items/bulk-unpublish`, { itemIds }),
};

export default publishApi;
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `npm run test:run -- --reporter verbose __tests__/api/publish.test.ts`
Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/utils/types.ts frontend/src/api/publish.ts frontend/src/__tests__/api/publish.test.ts
git commit -m "feat: add publish API module and update types for two-state visibility"
```

---

### Task 9: Remove Visibility from Frontend Create/Update Flows

**Files:**
- Modify: `frontend/src/api/collections.ts`
- Modify: `frontend/src/api/categories.ts`
- Modify: `frontend/src/api/items.ts`
- Modify: `frontend/src/api/workspaces.ts`
- Modify: `frontend/src/contexts/DataContext.tsx`
- Delete: `frontend/src/components/common/VisibilityToggle.tsx`

- [ ] **Step 1: Read all affected files**

Read each file to understand current visibility usage.

- [ ] **Step 2: Update tests referencing Visibility.Default or visibility in create/update**

Search tests for `Visibility.Default`, `visibility` in create/update calls. Update as needed.

- [ ] **Step 3: Run tests to verify failures**

Run: `npm run test:run`

- [ ] **Step 4: Remove visibility from API request types**

In `collections.ts`: Remove `visibility` from `CreateCollectionRequest` and `UpdateCollectionRequest`.
In `categories.ts`: Remove `visibility` from `CreateCategoryRequest` and `UpdateCategoryRequest`.
In `items.ts`: Remove `visibility` from any create/update request types.
In `workspaces.ts`: Remove `UpdatePublicAccessRequest`, `UpdatePublicAccessResponse`, and any `updatePublicAccess` function.

- [ ] **Step 5: Remove visibility from DataContext methods**

In `DataContext.tsx`: Remove `visibility` parameter from `addCollection`, `updateCollection`, `addCategory`, `updateCategory`, and equivalent item methods.

- [ ] **Step 6: Delete VisibilityToggle.tsx**

Remove `frontend/src/components/common/VisibilityToggle.tsx` and any associated test file. Search for imports of `VisibilityToggle` across the codebase and remove them.

- [ ] **Step 7: Run all tests**

Run: `npm run test:run`
Expected: All pass.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat: remove visibility from create/update flows, delete VisibilityToggle"
```

---

### Task 10: PublishButton and PublicBadge Components (Frontend)

**Files:**
- Create: `frontend/src/components/common/PublishButton.tsx`
- Create: `frontend/src/components/common/PublicBadge.tsx`
- Create: `frontend/src/styles/components/publish.css`
- Create: `frontend/src/__tests__/components/PublishButton.test.tsx`
- Create: `frontend/src/__tests__/components/PublicBadge.test.tsx`

- [ ] **Step 1: Write tests for PublishButton**

Test:
- Renders with up-arrow icon and "Publish" text
- Calls `onPublish` callback when clicked
- Has correct CSS classes for green styling
- Is hidden by default, visible on hover (via CSS class)

- [ ] **Step 2: Write tests for PublicBadge**

Test:
- Renders with eye icon and "Public" text when `effectiveIsPublic` is true
- Does not render when `effectiveIsPublic` is false
- Calls `onUnpublish` callback when clicked
- Has hover state classes for red unpublish treatment

- [ ] **Step 3: Run tests to verify they fail**

Run: `npm run test:run -- --reporter verbose __tests__/components/PublishButton.test.tsx __tests__/components/PublicBadge.test.tsx`

- [ ] **Step 4: Create publish.css**

Implement styles matching the approved mockups:
- `.publish-btn`: green (`#48bb78`), border-radius pill, hidden by default, visible on parent hover
- `.public-badge`: blue (`#63b3ed`), eye icon, always visible
- `.public-badge:hover`: red (`#f56565`), crossed-out eye, "Unpublish" text
- Transition: 0.15s ease for opacity, background, color changes

- [ ] **Step 5: Create PublishButton component**

```tsx
interface PublishButtonProps {
  onPublish: () => void;
  className?: string;
}
```

Green pill with up-arrow SVG icon. Calls `onPublish` on click. Stops event propagation (so clicking publish doesn't also navigate to item detail).

- [ ] **Step 6: Create PublicBadge component**

```tsx
interface PublicBadgeProps {
  effectiveIsPublic: boolean;
  onUnpublish: () => void;
  className?: string;
}
```

Blue pill with eye SVG icon. On hover, morphs to red with crossed-out eye and "Unpublish" text. Calls `onUnpublish` on click. Stops event propagation.

- [ ] **Step 7: Run tests to verify they pass**

Run: `npm run test:run -- --reporter verbose __tests__/components/PublishButton.test.tsx __tests__/components/PublicBadge.test.tsx`

- [ ] **Step 8: Commit**

```bash
git add frontend/src/components/common/PublishButton.tsx frontend/src/components/common/PublicBadge.tsx frontend/src/styles/components/publish.css frontend/src/__tests__/components/PublishButton.test.tsx frontend/src/__tests__/components/PublicBadge.test.tsx
git commit -m "feat: add PublishButton and PublicBadge components"
```

---

### Task 11: VisibilityFilter Component (Frontend)

**Files:**
- Create: `frontend/src/components/common/VisibilityFilter.tsx`
- Create: `frontend/src/styles/components/visibility-filter.css`
- Create: `frontend/src/__tests__/components/VisibilityFilter.test.tsx`

- [ ] **Step 1: Write tests for VisibilityFilter**

Test:
- Renders three filter buttons: All, Public, Private
- "All" is active by default
- Clicking a filter button calls `onFilterChange` with the filter value
- Shows item count: "Showing X items"
- Active button has active styling class

- [ ] **Step 2: Run tests to verify they fail**

Run: `npm run test:run -- --reporter verbose __tests__/components/VisibilityFilter.test.tsx`

- [ ] **Step 3: Create visibility-filter.css**

Implement styles matching the approved mockup:
- `.filter-bar`: segmented button group, dark background, rounded
- `.filter-btn`: neutral text, transitions on hover
- `.filter-btn.active`: highlighted background, white text
- Item card animation: `.item-card.hidden` with `opacity: 0`, `transform: scale(0.95)`, `transition: 0.25s ease`

- [ ] **Step 4: Create VisibilityFilter component**

```tsx
type VisibilityFilterValue = 'all' | 'public' | 'private';

interface VisibilityFilterProps {
  value: VisibilityFilterValue;
  onChange: (filter: VisibilityFilterValue) => void;
  totalCount: number;
  filteredCount: number;
}
```

Three buttons in a segmented control. Eye icon on the Public button. Shows "Showing X items" count.

- [ ] **Step 5: Run tests to verify they pass**

Run: `npm run test:run -- --reporter verbose __tests__/components/VisibilityFilter.test.tsx`

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/common/VisibilityFilter.tsx frontend/src/styles/components/visibility-filter.css frontend/src/__tests__/components/VisibilityFilter.test.tsx
git commit -m "feat: add VisibilityFilter component with CSS animation"
```

---

### Task 12: BulkActionBar Component (Frontend)

**Files:**
- Create: `frontend/src/components/common/BulkActionBar.tsx`
- Create: `frontend/src/__tests__/components/BulkActionBar.test.tsx`

- [ ] **Step 1: Write tests for BulkActionBar**

Test:
- Renders selected count
- Shows "Publish Selected" and "Make Private" buttons
- Shows "Cancel" button
- Calls `onPublish` when "Publish Selected" clicked
- Calls `onUnpublish` when "Make Private" clicked
- Calls `onCancel` when "Cancel" clicked
- Does not render when `selectedCount` is 0

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Create BulkActionBar component**

```tsx
interface BulkActionBarProps {
  selectedCount: number;
  onPublish: () => void;
  onUnpublish: () => void;
  onCancel: () => void;
}
```

Bar with count badge, "Publish Selected" (green), "Make Private" (neutral), "Cancel" buttons.

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/common/BulkActionBar.tsx frontend/src/__tests__/components/BulkActionBar.test.tsx
git commit -m "feat: add BulkActionBar component for bulk publish/unpublish"
```

---

### Task 13: Publish and Unpublish Confirm Modals (Frontend)

**Files:**
- Create: `frontend/src/components/common/PublishConfirmModal.tsx`
- Create: `frontend/src/components/common/UnpublishConfirmModal.tsx`
- Create: `frontend/src/__tests__/components/PublishConfirmModal.test.tsx`
- Create: `frontend/src/__tests__/components/UnpublishConfirmModal.test.tsx`

- [ ] **Step 1: Write tests for PublishConfirmModal**

Test:
- Renders entity name and item/category counts
- Shows two options: "Publish all" and "Publish container only"
- Calls `onConfirm(true)` when "Publish all" selected
- Calls `onConfirm(false)` when "Publish container only" selected
- Calls `onCancel` when cancelled

- [ ] **Step 2: Write tests for UnpublishConfirmModal**

Test:
- Renders entity name and affected counts
- Shows message about items being hidden but reappearing on re-publish
- Calls `onConfirm` when confirmed
- Calls `onCancel` when cancelled

- [ ] **Step 3: Run tests to verify they fail**

- [ ] **Step 4: Create PublishConfirmModal**

```tsx
interface PublishConfirmModalProps {
  entityType: 'category' | 'collection';
  entityName: string;
  itemCount: number;
  categoryCount?: number; // only for collections
  onConfirm: (includeChildren: boolean) => void;
  onCancel: () => void;
}
```

- [ ] **Step 5: Create UnpublishConfirmModal**

```tsx
interface UnpublishConfirmModalProps {
  entityType: 'category' | 'collection';
  entityName: string;
  affectedPublicItems: number;
  affectedPublicCategories?: number; // only for collections
  onConfirm: () => void;
  onCancel: () => void;
}
```

Message: "This [category/collection] has X items currently visible in your public gallery. They will be hidden, but if you make this [category/collection] public again, they'll reappear. Continue?"

- [ ] **Step 6: Run tests to verify they pass**

- [ ] **Step 7: Commit**

```bash
git add frontend/src/components/common/PublishConfirmModal.tsx frontend/src/components/common/UnpublishConfirmModal.tsx frontend/src/__tests__/components/PublishConfirmModal.test.tsx frontend/src/__tests__/components/UnpublishConfirmModal.test.tsx
git commit -m "feat: add publish and unpublish confirmation modals"
```

---

### Task 14: SlugSetupModal Component (Frontend)

**Files:**
- Create: `frontend/src/components/common/SlugSetupModal.tsx`
- Create: `frontend/src/__tests__/components/SlugSetupModal.test.tsx`

- [ ] **Step 1: Write tests for SlugSetupModal**

Test:
- Renders title "Set Up Your Public Gallery"
- Shows slug input field
- Pre-populates slug if provided via `existingSlug` prop
- Shows live URL preview
- Validates slug format (lowercase, alphanumeric, hyphens, 3-50 chars)
- Disables submit when slug is invalid
- Calls `onConfirm(slug)` when "Create Gallery & Publish" clicked
- Calls `onCancel` when cancelled
- Shows simpler message when `existingSlug` is provided

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Create SlugSetupModal**

```tsx
interface SlugSetupModalProps {
  existingSlug?: string | null;
  onConfirm: (slug: string) => void;
  onCancel: () => void;
}
```

Reuse the slug validation logic from `WorkspaceEditModal.tsx` (`toSlug`, `isValidSlug` helpers). Extract these to a shared utility if not already shared.

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/common/SlugSetupModal.tsx frontend/src/__tests__/components/SlugSetupModal.test.tsx
git commit -m "feat: add SlugSetupModal for first-publish flow"
```

---

### Task 15: Integrate Publish into ItemCard and ItemList (Frontend)

**Files:**
- Modify: `frontend/src/components/item/ItemCard.tsx`
- Modify: `frontend/src/components/item/ItemList.tsx`
- Modify: `frontend/src/contexts/DataContext.tsx`

- [ ] **Step 1: Read current ItemCard.tsx and ItemList.tsx**

Understand the current component structure, props, and rendering.

- [ ] **Step 2: Update existing tests for ItemCard and ItemList**

Add tests for:
- ItemCard shows PublicBadge when `effectiveIsPublic` is true
- ItemCard shows PublishButton on hover when item is private
- ItemCard supports selection mode (checkbox overlay)
- ItemList renders VisibilityFilter
- ItemList filters items based on selected filter
- ItemList supports bulk selection with BulkActionBar

- [ ] **Step 3: Run tests to verify they fail**

- [ ] **Step 4: Add publish/unpublish methods to DataContext**

Add methods that call the publish API and update local state:

```typescript
publishItem: (itemId: number) => Promise<PublishResponse>;
unpublishItem: (itemId: number) => Promise<UnpublishResponse>;
publishCategory: (categoryId: number, includeChildren: boolean) => Promise<PublishResponse>;
unpublishCategory: (categoryId: number) => Promise<UnpublishResponse>;
publishCollection: (collectionId: number, includeChildren: boolean) => Promise<PublishResponse>;
unpublishCollection: (collectionId: number) => Promise<UnpublishResponse>;
bulkPublishItems: (itemIds: number[]) => Promise<BulkPublishResponse>;
bulkUnpublishItems: (itemIds: number[]) => Promise<BulkUnpublishResponse>;
getUnpublishCategoryPreview: (categoryId: number) => Promise<UnpublishPreviewResponse>;
getUnpublishCollectionPreview: (collectionId: number) => Promise<UnpublishPreviewResponse>;
```

Each method should call the API, then refresh local data to reflect changes.

- [ ] **Step 5: Integrate PublishButton and PublicBadge into ItemCard**

Add to ItemCard:
- If `effectiveIsPublic`: show `PublicBadge` in top-right corner
- If not `effectiveIsPublic`: show `PublishButton` (visible on hover via CSS)
- Wire callbacks to DataContext publish/unpublish methods
- Handle `requiresSlugSetup` response by showing SlugSetupModal
- After user completes slug setup in the modal, automatically retry the original publish action so the user doesn't have to click publish again (the spec requires "the original publish action completes automatically")

- [ ] **Step 6: Add VisibilityFilter and BulkActionBar to ItemList**

Add to ItemList:
- VisibilityFilter above the grid
- State for filter value and selected items
- Filter items based on `effectiveIsPublic` and selected filter
- Checkbox overlay on cards when in selection mode
- BulkActionBar when items are selected
- CSS animation classes on item cards for filter transitions

- [ ] **Step 7: Run all tests**

Run: `npm run test:run`
Expected: All pass.

- [ ] **Step 8: Commit**

```bash
git add frontend/src/components/item/ItemCard.tsx frontend/src/components/item/ItemList.tsx frontend/src/contexts/DataContext.tsx
git commit -m "feat: integrate publish/unpublish into ItemCard and ItemList"
```

---

### Task 16: Integrate Publish into Category and Collection Views (Frontend)

**Files:**
- Modify: Category list/tree components (find exact paths by reading the codebase)
- Modify: Collection view components

- [ ] **Step 1: Read category and collection view components**

Find and read the components that render category lists and collection headers. Identify where to add publish/unpublish buttons.

- [ ] **Step 2: Update tests for category and collection views**

Add tests for publish/unpublish buttons, confirm modals, and toast notifications on categories and collections.

- [ ] **Step 3: Run tests to verify they fail**

- [ ] **Step 4: Add PublishButton/PublicBadge to category entries**

Same pattern as ItemCard: PublicBadge for public categories, PublishButton for private. Wire to DataContext methods. Show PublishConfirmModal when publishing a category (prompts for includeChildren). Show UnpublishConfirmModal when unpublishing (fetches preview first).

- [ ] **Step 5: Add PublishButton/PublicBadge to collection header**

Same pattern. Show PublishConfirmModal when publishing. Show UnpublishConfirmModal when unpublishing.

- [ ] **Step 6: Run all tests**

Run: `npm run test:run`
Expected: All pass.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: integrate publish/unpublish into category and collection views"
```

---

### Task 17: Update WorkspaceEditModal and App Header (Frontend)

**Files:**
- Modify: `frontend/src/components/workspace/WorkspaceEditModal.tsx`
- Modify: `frontend/src/App.tsx`

- [ ] **Step 1: Read current WorkspaceEditModal.tsx and App.tsx**

Understand the current layout and where changes fit.

- [ ] **Step 2: Update tests**

- WorkspaceEditModal: Remove tests for `IsPublicAccessEnabled` checkbox. Add test for slug reservation note.
- App.tsx: Add test for "Public Gallery" link in header when slug exists. Add test for "Set Up Public Gallery" link when no slug.

- [ ] **Step 3: Run tests to verify they fail**

- [ ] **Step 4: Update WorkspaceEditModal**

- Remove the `IsPublicAccessEnabled` checkbox and related state/logic
- Keep the slug input field
- Add note below slug field: "Reserve your gallery URL. Your gallery becomes active when you publish your first item."
- Remove the separate public access API call from submit handler

- [ ] **Step 5: Add Public Gallery link to App header**

In `App.tsx` (or the header component):
- If workspace has a slug: show a globe icon + "Public Gallery" link that opens `/public/{slug}` in a new tab
- If workspace has no slug: show "Set Up Public Gallery" link that opens WorkspaceEditModal or navigates to settings

- [ ] **Step 6: Run all tests**

Run: `npm run test:run`
Expected: All pass.

- [ ] **Step 7: Commit**

```bash
git add frontend/src/components/workspace/WorkspaceEditModal.tsx frontend/src/App.tsx
git commit -m "feat: update workspace settings and add Public Gallery header link"
```

---

### Task 18: Toast Notifications for Publish Actions (Frontend)

**Files:**
- Determine if a toast system already exists (check for existing toast/notification components)
- Create or modify toast component as needed

- [ ] **Step 1: Check for existing toast/notification infrastructure**

Search the codebase for toast, notification, alert, or snackbar components.

- [ ] **Step 2: Write tests for publish toast behavior**

Test that after a publish action, a toast appears showing:
- The published entity name
- Any promoted parents (if auto-promotion occurred)

- [ ] **Step 3: Run tests to verify they fail**

- [ ] **Step 4: Implement publish toast**

If a toast system exists, integrate with it. If not, create a minimal toast component. Wire it into the publish flow — after each successful publish, show the toast with information from the `PublishResponse`.

- [ ] **Step 5: Run all tests**

Run: `npm run test:run`
Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: add toast notifications for publish actions"
```

---

### Task 19: End-to-End Verification

- [ ] **Step 1: Run all backend tests**

Run: `dotnet test backend/tests/backend.tests`
Expected: All pass, 100% coverage on new code.

- [ ] **Step 2: Run all frontend tests**

Run: `npm run test:run`
Expected: All pass, 100% coverage on new code.

- [ ] **Step 3: Run frontend lint**

Run: `npm run lint`
Expected: No errors.

- [ ] **Step 4: Build frontend**

Run: `npm run build`
Expected: Clean build, no warnings.

- [ ] **Step 5: Manual smoke test**

Start the full stack with `./scripts/dev-start.sh` and verify:
- Publishing an item from the card hover button works
- Auto-promotion toast shows promoted parents
- First-publish modal appears when workspace has no slug
- Visibility filter works with animation
- Bulk selection and publish works
- Publishing a category shows the confirm modal with options
- Unpublishing a category shows the confirm modal with counts
- Public Gallery link appears in header
- Public gallery shows only published items
- Making an item private hides it from the gallery

- [ ] **Step 6: Commit any fixes**

```bash
git add -A
git commit -m "fix: address issues found during smoke testing"
```
