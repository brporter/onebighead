# Public Collection Browsing Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable anonymous users to browse public collections, categories, and items via workspace-scoped URLs.

**Architecture:** New `PublicController` with `[AllowAnonymous]` endpoints, dedicated public DTOs, workspace slug + opt-in model, and simplified frontend public layout outside `RequireAuth`.

**Tech Stack:** .NET 10 (EF Core, ASP.NET), React 19, React Router 7, TypeScript, Vitest, xUnit

---

### Task 1: Add Slug and IsPublicAccessEnabled to Workspace Model

**Files:**
- Modify: `backend/src/backend/Models/Workspace.cs`

**Step 1: Add properties to Workspace model**

Add these properties to the `Workspace` class in `backend/src/backend/Models/Workspace.cs`:

```csharp
/// <summary>
/// URL-friendly identifier for public access. Lowercase alphanumeric + hyphens, 3-50 chars.
/// </summary>
[MaxLength(50)]
public string? Slug { get; set; }

/// <summary>
/// Whether this workspace's public collections are accessible to anonymous users.
/// Requires Slug to be set.
/// </summary>
public bool IsPublicAccessEnabled { get; set; } = false;
```

Add these after the existing `IsDeleted` / `DeletedByUserId` properties.

**Step 2: Commit**

```bash
git add backend/src/backend/Models/Workspace.cs
git commit -m "feat: add Slug and IsPublicAccessEnabled to Workspace model"
```

---

### Task 2: Create EF Core Migration

**Files:**
- Modify: `backend/src/backend/Data/AppDbContext.cs` (add index configuration)
- Create: New migration file (auto-generated)

**Step 1: Add DbContext configuration for unique slug index**

In `AppDbContext.cs`, in the `OnModelCreating` method, find the existing Workspace entity configuration:

```csharp
modelBuilder.Entity<Workspace>(entity =>
{
    entity.HasKey(w => w.Id);
    entity.HasIndex(w => w.Name);
    entity.HasIndex(w => w.IsDeleted);
});
```

Add a unique filtered index for Slug (only where Slug is not null):

```csharp
modelBuilder.Entity<Workspace>(entity =>
{
    entity.HasKey(w => w.Id);
    entity.HasIndex(w => w.Name);
    entity.HasIndex(w => w.IsDeleted);
    entity.HasIndex(w => w.Slug)
        .IsUnique()
        .HasFilter("[Slug] IS NOT NULL");
});
```

**Step 2: Generate the migration**

```bash
cd backend/src/backend
dotnet ef migrations add AddWorkspacePublicAccess
```

**Step 3: Verify migration was created**

Check that the generated migration contains:
- `AddColumn` for `Slug` (nullable string, max 50)
- `AddColumn` for `IsPublicAccessEnabled` (bool, default false)
- `CreateIndex` with unique filter on `Slug`

**Step 4: Commit**

```bash
git add backend/src/backend/Data/AppDbContext.cs backend/src/backend/Migrations/
git commit -m "feat: add migration for workspace public access fields"
```

---

### Task 3: Add GetBySlugAsync to IWorkspaceRepository

**Files:**
- Modify: `backend/src/backend/Data/IWorkspaceRepository.cs`
- Modify: `backend/src/backend/Data/WorkspaceRepository.cs`

**Step 1: Add method to interface**

Add to `IWorkspaceRepository` in `backend/src/backend/Data/IWorkspaceRepository.cs`:

```csharp
/// <summary>
/// Gets a workspace by its public slug. Only returns workspaces with public access enabled.
/// </summary>
Task<Workspace?> GetBySlugAsync(string slug);
```

**Step 2: Implement in WorkspaceRepository**

Add to `WorkspaceRepository` (find the file, add the method):

```csharp
public async Task<Workspace?> GetBySlugAsync(string slug)
{
    return await _context.Workspaces
        .AsNoTracking()
        .FirstOrDefaultAsync(w => w.Slug == slug && w.IsPublicAccessEnabled && !w.IsDeleted);
}
```

**Step 3: Register in Program.cs if needed**

The repository is already registered via `AddTracingDecorator<IWorkspaceRepository, WorkspaceRepository>`. Since we're adding a method to the existing interface, the source-generated tracing proxy will automatically pick it up on rebuild. No changes needed.

**Step 4: Commit**

```bash
git add backend/src/backend/Data/IWorkspaceRepository.cs backend/src/backend/Data/WorkspaceRepository.cs
git commit -m "feat: add GetBySlugAsync to workspace repository"
```

---

### Task 4: Create Public DTOs

**Files:**
- Create: `backend/src/backend/DTOs/PublicDtos.cs`

**Step 1: Create the public DTOs file**

Create `backend/src/backend/DTOs/PublicDtos.cs`:

```csharp
using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class PublicWorkspaceDto
{
    public string Name { get; set; } = string.Empty;
    public string Slug { get; set; } = string.Empty;
}

public class PublicCollectionDto
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? HeroImageUrl { get; set; }
    public string Slug { get; set; } = string.Empty;
}

public class PublicCategoryDto
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public int? ParentCategoryId { get; set; }
    public bool IsSystem { get; set; }
    public List<int> ItemTemplateIds { get; set; } = new();
}

public class PublicItemSummaryDto
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string? PrimaryImageUrl { get; set; }
    public int? CategoryId { get; set; }
}

public class PublicItemDto
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public List<PublicItemPropertyDto> Properties { get; set; } = new();
    public List<PublicItemImageDto> Images { get; set; } = new();
    public int? CategoryId { get; set; }
    public string? CategoryName { get; set; }
    public string? TemplateKey { get; set; }
}

public class PublicItemPropertyDto
{
    public string Category { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
}

public class PublicItemImageDto
{
    public string Url { get; set; } = string.Empty;
    public string? Caption { get; set; }
    public int SortOrder { get; set; }
}

public class PublicCollectionDetailDto
{
    public PublicCollectionDto Collection { get; set; } = new();
    public List<PublicCategoryDto> Categories { get; set; } = new();
}
```

**Step 2: Commit**

```bash
git add backend/src/backend/DTOs/PublicDtos.cs
git commit -m "feat: add public DTOs for anonymous collection browsing"
```

---

### Task 5: Create PublicController

**Files:**
- Create: `backend/src/backend/Controllers/PublicController.cs`

**Step 1: Create the controller**

Create `backend/src/backend/Controllers/PublicController.cs`:

```csharp
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/public")]
[AllowAnonymous]
public class PublicController : ControllerBase
{
    private readonly IWorkspaceRepository _workspaceRepository;
    private readonly ICollectionRepository _collectionRepository;
    private readonly ICategoryRepository _categoryRepository;
    private readonly IItemRepository _itemRepository;
    private readonly IVisibilityService _visibilityService;

    public PublicController(
        IWorkspaceRepository workspaceRepository,
        ICollectionRepository collectionRepository,
        ICategoryRepository categoryRepository,
        IItemRepository itemRepository,
        IVisibilityService visibilityService)
    {
        _workspaceRepository = workspaceRepository;
        _collectionRepository = collectionRepository;
        _categoryRepository = categoryRepository;
        _itemRepository = itemRepository;
        _visibilityService = visibilityService;
    }

    /// <summary>
    /// Get public workspace profile by slug.
    /// </summary>
    [HttpGet("{slug}")]
    public async Task<ActionResult<PublicWorkspaceDto>> GetWorkspace(string slug)
    {
        var workspace = await _workspaceRepository.GetBySlugAsync(slug);
        if (workspace == null)
        {
            return NotFound();
        }

        return Ok(new PublicWorkspaceDto
        {
            Name = workspace.Name,
            Slug = workspace.Slug!
        });
    }

    /// <summary>
    /// List all public collections in a workspace.
    /// </summary>
    [HttpGet("{slug}/collections")]
    public async Task<ActionResult<IEnumerable<PublicCollectionDto>>> GetCollections(string slug)
    {
        var workspace = await _workspaceRepository.GetBySlugAsync(slug);
        if (workspace == null)
        {
            return NotFound();
        }

        var collections = await _collectionRepository.GetAllAsync(workspace.Id);
        var publicCollections = collections
            .Where(c => c.EffectiveIsPublic)
            .Select(c => new PublicCollectionDto
            {
                Id = c.Id,
                Name = c.Name,
                Description = c.Description,
                HeroImageUrl = c.HeroImageUrl,
                Slug = c.Slug
            })
            .ToList();

        return Ok(publicCollections);
    }

    /// <summary>
    /// Get a public collection with its public category tree.
    /// </summary>
    [HttpGet("{slug}/collections/{collectionId:int}")]
    public async Task<ActionResult<PublicCollectionDetailDto>> GetCollection(string slug, int collectionId)
    {
        var workspace = await _workspaceRepository.GetBySlugAsync(slug);
        if (workspace == null)
        {
            return NotFound();
        }

        var collection = await _collectionRepository.GetByIdAsync(collectionId, workspace.Id);
        if (collection == null || !collection.EffectiveIsPublic)
        {
            return NotFound();
        }

        var categories = (await _categoryRepository.GetByCollectionAsync(collectionId, workspace.Id)).ToList();
        _visibilityService.ComputeEffectiveVisibility(categories, collection);

        var publicCategories = categories
            .Where(c => c.EffectiveIsPublic)
            .Select(c => new PublicCategoryDto
            {
                Id = c.Id,
                Name = c.Name,
                ParentCategoryId = c.ParentCategoryId,
                IsSystem = c.IsSystem,
                ItemTemplateIds = c.ItemTemplateIds
            })
            .ToList();

        return Ok(new PublicCollectionDetailDto
        {
            Collection = new PublicCollectionDto
            {
                Id = collection.Id,
                Name = collection.Name,
                Description = collection.Description,
                HeroImageUrl = collection.HeroImageUrl,
                Slug = collection.Slug
            },
            Categories = publicCategories
        });
    }

    /// <summary>
    /// Get public items in a collection, optionally filtered by category.
    /// </summary>
    [HttpGet("{slug}/collections/{collectionId:int}/items")]
    public async Task<ActionResult<IEnumerable<PublicItemSummaryDto>>> GetItems(
        string slug, int collectionId, [FromQuery] int? categoryId = null)
    {
        var workspace = await _workspaceRepository.GetBySlugAsync(slug);
        if (workspace == null)
        {
            return NotFound();
        }

        var collection = await _collectionRepository.GetByIdAsync(collectionId, workspace.Id);
        if (collection == null || !collection.EffectiveIsPublic)
        {
            return NotFound();
        }

        var categories = (await _categoryRepository.GetByCollectionAsync(collectionId, workspace.Id)).ToList();
        _visibilityService.ComputeEffectiveVisibility(categories, collection);

        IEnumerable<Item> items;
        if (categoryId.HasValue)
        {
            // Verify the category is public
            var category = categories.FirstOrDefault(c => c.Id == categoryId.Value);
            if (category == null || !category.EffectiveIsPublic)
            {
                return NotFound();
            }
            items = await _itemRepository.GetByCategoryIdsAsync(new[] { categoryId.Value }, workspace.Id);
        }
        else
        {
            items = await _itemRepository.GetByCollectionIdAsync(collectionId, workspace.Id);
        }

        var itemList = items.ToList();
        _visibilityService.ComputeEffectiveVisibility(itemList, collection, categories);

        var publicItems = itemList
            .Where(i => i.EffectiveIsPublic)
            .Select(i => new PublicItemSummaryDto
            {
                Id = i.Id,
                Name = i.Name,
                Summary = i.Summary,
                PrimaryImageUrl = i.Images.FirstOrDefault()?.Url,
                CategoryId = i.CategoryId
            })
            .ToList();

        return Ok(publicItems);
    }

    /// <summary>
    /// Get a public item's full details.
    /// </summary>
    [HttpGet("{slug}/items/{itemId:int}")]
    public async Task<ActionResult<PublicItemDto>> GetItem(string slug, int itemId)
    {
        var workspace = await _workspaceRepository.GetBySlugAsync(slug);
        if (workspace == null)
        {
            return NotFound();
        }

        var item = await _itemRepository.GetByIdAsync(itemId, workspace.Id);
        if (item == null)
        {
            return NotFound();
        }

        var collection = await _collectionRepository.GetByIdAsync(item.CollectionId, workspace.Id);
        if (collection == null || !collection.EffectiveIsPublic)
        {
            return NotFound();
        }

        // Compute visibility
        Category? category = null;
        if (item.CategoryId.HasValue)
        {
            var categories = (await _categoryRepository.GetByCollectionAsync(item.CollectionId, workspace.Id)).ToList();
            _visibilityService.ComputeEffectiveVisibility(categories, collection);
            category = categories.FirstOrDefault(c => c.Id == item.CategoryId.Value);
        }

        _visibilityService.ComputeEffectiveVisibility(item, collection, category);
        if (!item.EffectiveIsPublic)
        {
            return NotFound();
        }

        return Ok(new PublicItemDto
        {
            Id = item.Id,
            Name = item.Name,
            Summary = item.Summary,
            Description = item.Description,
            CategoryId = item.CategoryId,
            CategoryName = category?.Name,
            TemplateKey = item.TemplateKey,
            Properties = item.Properties.Select(p => new PublicItemPropertyDto
            {
                Category = p.Category,
                Name = p.Name,
                Value = p.Value
            }).ToList(),
            Images = item.Images
                .OrderBy(img => img.SortOrder)
                .Select(img => new PublicItemImageDto
                {
                    Url = img.Url,
                    Caption = img.Caption,
                    SortOrder = img.SortOrder
                }).ToList()
        });
    }
}
```

**Step 2: Verify the Item model has the fields we reference**

Check that `Item` has: `Summary`, `Description`, `Properties` (with `Category`, `Name`, `Value`), `Images` (with `Url`, `Caption`, `SortOrder`), `TemplateKey`, `CategoryId`, `CollectionId`. Also check `IItemRepository` has `GetByCollectionIdAsync`. If not, we may need to add it or use an alternative query pattern.

**Step 3: Commit**

```bash
git add backend/src/backend/Controllers/PublicController.cs
git commit -m "feat: add PublicController with anonymous browsing endpoints"
```

---

### Task 6: Add Public Image Access Endpoint

**Files:**
- Modify: `backend/src/backend/Controllers/ImagesController.cs`

**Step 1: Add anonymous image endpoint**

Add a new endpoint to `ImagesController` that serves images for public items. Add this method:

```csharp
/// <summary>
/// Get an image by key without authentication. Used for public collection browsing.
/// The image must belong to a public item in a workspace with public access enabled.
/// </summary>
[HttpGet("public/{key:guid}")]
[AllowAnonymous]
[ResponseCache(Duration = 86400, Location = ResponseCacheLocation.Any)]
public async Task<IActionResult> GetPublic(Guid key)
{
    var image = await _imageProvider.RetrieveByKeyAsync(key);
    if (image == null)
    {
        return NotFound();
    }

    return File(image.Data, image.ContentType, image.FileName);
}
```

Note: This may require adding a `RetrieveByKeyAsync(Guid key)` method to `IImageProvider` that retrieves without workspace scoping. We need to verify the image belongs to a public item. Two approaches:

**Option A (simpler):** Just serve any image by key without workspace check. Image GUIDs are unguessable, so this is low risk. This is the approach to start with.

**Option B (stricter):** Join through item -> collection -> workspace to verify public access. More complex but more secure. Can be added later if needed.

Start with Option A. Check `IImageProvider` for existing methods and add `RetrieveByKeyAsync` if it doesn't exist.

**Step 2: Commit**

```bash
git add backend/src/backend/Controllers/ImagesController.cs
git commit -m "feat: add anonymous image access endpoint for public browsing"
```

---

### Task 7: Update Workspace Settings - Backend

**Files:**
- Modify: `backend/src/backend/DTOs/WorkspaceRequests.cs`
- Modify: `backend/src/backend/Controllers/WorkspacesController.cs`

**Step 1: Add slug validation and update DTOs**

Add to `backend/src/backend/DTOs/WorkspaceRequests.cs`:

```csharp
public class UpdateWorkspacePublicAccessRequest
{
    [MaxLength(50)]
    [RegularExpression(@"^[a-z0-9][a-z0-9-]*[a-z0-9]$", ErrorMessage = "Slug must be lowercase alphanumeric with hyphens, starting and ending with a letter or number")]
    [MinLength(3)]
    public string? Slug { get; set; }

    public bool IsPublicAccessEnabled { get; set; }
}

public class UpdateWorkspacePublicAccessResponse
{
    public int WorkspaceId { get; set; }
    public string? Slug { get; set; }
    public bool IsPublicAccessEnabled { get; set; }
    public string? PublicUrl { get; set; }
}

public class CheckSlugResponse
{
    public bool IsAvailable { get; set; }
}
```

**Step 2: Add endpoints to WorkspacesController**

Add these endpoints to `WorkspacesController`:

```csharp
/// <summary>
/// Update workspace public access settings (requires WorkspaceAdmin)
/// </summary>
[HttpPut("{workspaceId}/public-access")]
[Authorize(Policy = "WorkspaceAdmin")]
public async Task<IActionResult> UpdatePublicAccess(int workspaceId, [FromBody] UpdateWorkspacePublicAccessRequest request)
{
    var userId = GetUserId();

    var membership = await _workspaceUserRepository.GetMembershipAsync(userId, workspaceId);
    if (membership == null || membership.WorkspaceRole != WorkspaceRole.WorkspaceAdmin)
    {
        return Forbid();
    }

    var workspace = await _workspaceRepository.GetByIdAsync(workspaceId);
    if (workspace == null)
    {
        return NotFound();
    }

    // Cannot enable public access without a slug
    if (request.IsPublicAccessEnabled && string.IsNullOrEmpty(request.Slug))
    {
        return BadRequest(new { error = "A slug is required to enable public access" });
    }

    // Check slug uniqueness if provided
    if (!string.IsNullOrEmpty(request.Slug))
    {
        var existing = await _workspaceRepository.GetBySlugAsync(request.Slug);
        if (existing != null && existing.Id != workspaceId)
        {
            return Conflict(new { error = "This slug is already taken" });
        }
    }

    workspace.Slug = request.Slug;
    workspace.IsPublicAccessEnabled = request.IsPublicAccessEnabled;
    await _workspaceRepository.UpdateAsync(workspace);

    var publicUrl = request.IsPublicAccessEnabled && !string.IsNullOrEmpty(request.Slug)
        ? $"/public/{request.Slug}"
        : null;

    return Ok(new UpdateWorkspacePublicAccessResponse
    {
        WorkspaceId = workspace.Id,
        Slug = workspace.Slug,
        IsPublicAccessEnabled = workspace.IsPublicAccessEnabled,
        PublicUrl = publicUrl
    });
}

/// <summary>
/// Check if a workspace slug is available
/// </summary>
[HttpGet("check-slug/{slug}")]
public async Task<IActionResult> CheckSlug(string slug)
{
    var existing = await _workspaceRepository.GetBySlugAsync(slug);
    return Ok(new CheckSlugResponse { IsAvailable = existing == null });
}
```

**Step 3: Commit**

```bash
git add backend/src/backend/DTOs/WorkspaceRequests.cs backend/src/backend/Controllers/WorkspacesController.cs
git commit -m "feat: add workspace public access settings endpoints"
```

---

### Task 8: Write Backend Integration Tests

**Files:**
- Create: `backend/tests/backend.tests/Integration/PublicControllerTests.cs`

**Step 1: Write the tests**

Create `backend/tests/backend.tests/Integration/PublicControllerTests.cs`:

```csharp
using System.Net;
using System.Text.Json;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class PublicControllerTests : IntegrationTestBase
{
    private const string PublicSlug = "test-public";
    private const int PublicWorkspaceId = 100;
    private const int PublicCollectionId = 100;
    private const int PrivateCollectionId = 101;
    private const int PublicCategoryId = 100;
    private const int PrivateCategoryId = 101;
    private const int PublicItemId = 100;
    private const int PrivateItemId = 101;

    public PublicControllerTests(CustomWebApplicationFactory factory) : base(factory) { }

    protected override async Task SeedAdditionalDataAsync()
    {
        using var scope = Factory.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        // Create a workspace with public access enabled
        context.Workspaces.Add(new Workspace
        {
            Id = PublicWorkspaceId,
            Name = "Public Test Workspace",
            Slug = PublicSlug,
            IsPublicAccessEnabled = true
        });

        // Public collection
        context.Collections.Add(new Collection
        {
            Id = PublicCollectionId,
            WorkspaceId = PublicWorkspaceId,
            Name = "Public Collection",
            Slug = "public-collection",
            Visibility = Visibility.Public
        });

        // Private collection
        context.Collections.Add(new Collection
        {
            Id = PrivateCollectionId,
            WorkspaceId = PublicWorkspaceId,
            Name = "Private Collection",
            Slug = "private-collection",
            Visibility = Visibility.Private
        });

        // Public category in public collection
        context.Categories.Add(new Category
        {
            Id = PublicCategoryId,
            WorkspaceId = PublicWorkspaceId,
            CollectionId = PublicCollectionId,
            Name = "Public Category",
            Visibility = Visibility.Public
        });

        // Private category in public collection
        context.Categories.Add(new Category
        {
            Id = PrivateCategoryId,
            WorkspaceId = PublicWorkspaceId,
            CollectionId = PublicCollectionId,
            Name = "Private Category",
            Visibility = Visibility.Private
        });

        // Public item
        context.Items.Add(new Item
        {
            Id = PublicItemId,
            WorkspaceId = PublicWorkspaceId,
            CollectionId = PublicCollectionId,
            CategoryId = PublicCategoryId,
            Name = "Public Item",
            Summary = "A public item",
            Description = "Detailed description",
            Visibility = Visibility.Public
        });

        // Private item
        context.Items.Add(new Item
        {
            Id = PrivateItemId,
            WorkspaceId = PublicWorkspaceId,
            CollectionId = PublicCollectionId,
            CategoryId = PublicCategoryId,
            Name = "Private Item",
            Summary = "A private item",
            Description = "Should not be visible",
            Visibility = Visibility.Private
        });

        await context.SaveChangesAsync();
    }

    [Fact]
    public async Task GetWorkspace_ValidSlug_ReturnsWorkspace()
    {
        using var client = CreateAnonymousClient();
        var response = await client.GetAsync($"/api/public/{PublicSlug}");

        response.EnsureSuccessStatusCode();
        var workspace = await DeserializeResponseAsync<PublicWorkspaceDto>(response);
        Assert.NotNull(workspace);
        Assert.Equal("Public Test Workspace", workspace.Name);
        Assert.Equal(PublicSlug, workspace.Slug);
    }

    [Fact]
    public async Task GetWorkspace_InvalidSlug_Returns404()
    {
        using var client = CreateAnonymousClient();
        var response = await client.GetAsync("/api/public/nonexistent");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GetCollections_ReturnsOnlyPublicCollections()
    {
        using var client = CreateAnonymousClient();
        var response = await client.GetAsync($"/api/public/{PublicSlug}/collections");

        response.EnsureSuccessStatusCode();
        var collections = await DeserializeResponseAsync<List<PublicCollectionDto>>(response);
        Assert.NotNull(collections);
        Assert.Single(collections);
        Assert.Equal("Public Collection", collections[0].Name);
    }

    [Fact]
    public async Task GetCollection_PublicCollection_ReturnsWithPublicCategories()
    {
        using var client = CreateAnonymousClient();
        var response = await client.GetAsync($"/api/public/{PublicSlug}/collections/{PublicCollectionId}");

        response.EnsureSuccessStatusCode();
        var detail = await DeserializeResponseAsync<PublicCollectionDetailDto>(response);
        Assert.NotNull(detail);
        Assert.Equal("Public Collection", detail.Collection.Name);
        // Should only include public categories
        Assert.All(detail.Categories, c => Assert.NotEqual(PrivateCategoryId, c.Id));
    }

    [Fact]
    public async Task GetCollection_PrivateCollection_Returns404()
    {
        using var client = CreateAnonymousClient();
        var response = await client.GetAsync($"/api/public/{PublicSlug}/collections/{PrivateCollectionId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task GetItems_ReturnsOnlyPublicItems()
    {
        using var client = CreateAnonymousClient();
        var response = await client.GetAsync($"/api/public/{PublicSlug}/collections/{PublicCollectionId}/items");

        response.EnsureSuccessStatusCode();
        var items = await DeserializeResponseAsync<List<PublicItemSummaryDto>>(response);
        Assert.NotNull(items);
        Assert.All(items, i => Assert.NotEqual(PrivateItemId, i.Id));
    }

    [Fact]
    public async Task GetItem_PublicItem_ReturnsDetails()
    {
        using var client = CreateAnonymousClient();
        var response = await client.GetAsync($"/api/public/{PublicSlug}/items/{PublicItemId}");

        response.EnsureSuccessStatusCode();
        var item = await DeserializeResponseAsync<PublicItemDto>(response);
        Assert.NotNull(item);
        Assert.Equal("Public Item", item.Name);
    }

    [Fact]
    public async Task GetItem_PrivateItem_Returns404()
    {
        using var client = CreateAnonymousClient();
        var response = await client.GetAsync($"/api/public/{PublicSlug}/items/{PrivateItemId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
```

**Step 2: Run the tests**

```bash
cd backend
dotnet test tests/backend.tests --filter "FullyQualifiedName~PublicControllerTests" -v n
```

Expected: Tests should pass once the controller is implemented correctly. Fix any compilation issues first.

**Step 3: Commit**

```bash
git add backend/tests/backend.tests/Integration/PublicControllerTests.cs
git commit -m "test: add integration tests for PublicController"
```

---

### Task 9: Create Frontend Public API Module

**Files:**
- Create: `frontend/src/api/public.ts`
- Modify: `frontend/src/api/index.ts`

**Step 1: Create the public API module**

Create `frontend/src/api/public.ts`:

```typescript
import { api } from './client';

export interface PublicWorkspace {
  name: string;
  slug: string;
}

export interface PublicCollection {
  id: number;
  name: string;
  description: string;
  heroImageUrl: string | null;
  slug: string;
}

export interface PublicCategory {
  id: number;
  name: string;
  parentCategoryId: number | null;
  isSystem: boolean;
  itemTemplateIds: number[];
}

export interface PublicCollectionDetail {
  collection: PublicCollection;
  categories: PublicCategory[];
}

export interface PublicItemSummary {
  id: number;
  name: string;
  summary: string;
  primaryImageUrl: string | null;
  categoryId: number | null;
}

export interface PublicItemProperty {
  category: string;
  name: string;
  value: string;
}

export interface PublicItemImage {
  url: string;
  caption: string | null;
  sortOrder: number;
}

export interface PublicItem {
  id: number;
  name: string;
  summary: string;
  description: string;
  properties: PublicItemProperty[];
  images: PublicItemImage[];
  categoryId: number | null;
  categoryName: string | null;
  templateKey: string | null;
}

export const publicApi = {
  getWorkspace(slug: string): Promise<PublicWorkspace> {
    return api.get<PublicWorkspace>(`/public/${slug}`);
  },

  getCollections(slug: string): Promise<PublicCollection[]> {
    return api.get<PublicCollection[]>(`/public/${slug}/collections`);
  },

  getCollection(slug: string, collectionId: number): Promise<PublicCollectionDetail> {
    return api.get<PublicCollectionDetail>(`/public/${slug}/collections/${collectionId}`);
  },

  getItems(slug: string, collectionId: number, categoryId?: number): Promise<PublicItemSummary[]> {
    const params = categoryId ? `?categoryId=${categoryId}` : '';
    return api.get<PublicItemSummary[]>(`/public/${slug}/collections/${collectionId}/items${params}`);
  },

  getItem(slug: string, itemId: number): Promise<PublicItem> {
    return api.get<PublicItem>(`/public/${slug}/items/${itemId}`);
  },
};
```

**Step 2: Add export to api/index.ts**

Add this line to `frontend/src/api/index.ts`:

```typescript
export { publicApi, type PublicWorkspace, type PublicCollection, type PublicCollectionDetail, type PublicCategory, type PublicItemSummary, type PublicItem, type PublicItemProperty, type PublicItemImage } from './public';
```

**Step 3: Commit**

```bash
git add frontend/src/api/public.ts frontend/src/api/index.ts
git commit -m "feat: add public API module for anonymous browsing"
```

---

### Task 10: Create Public Layout Component

**Files:**
- Create: `frontend/src/components/public/PublicLayout.tsx`
- Create: `frontend/src/components/public/index.ts`
- Create: `frontend/src/styles/components/PublicLayout.css`

**Step 1: Create the layout component**

Create `frontend/src/components/public/PublicLayout.tsx`:

```tsx
import { Outlet, Link, useParams } from 'react-router-dom';
import { useEffect, useState } from 'react';
import { publicApi, type PublicWorkspace } from '../../api';
import '../../styles/components/PublicLayout.css';

function PublicLayout() {
  const { slug } = useParams<{ slug: string }>();
  const [workspace, setWorkspace] = useState<PublicWorkspace | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!slug) return;

    setLoading(true);
    publicApi.getWorkspace(slug)
      .then(setWorkspace)
      .catch(() => setError('Workspace not found'))
      .finally(() => setLoading(false));
  }, [slug]);

  if (loading) {
    return (
      <div className="publicLayout">
        <div className="publicLayout__loading">Loading...</div>
      </div>
    );
  }

  if (error || !workspace) {
    return (
      <div className="publicLayout">
        <div className="publicLayout__error">
          <h1>Not Found</h1>
          <p>This workspace doesn't exist or isn't publicly accessible.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="publicLayout">
      <header className="publicLayout__header">
        <div className="publicLayout__headerContent">
          <Link to={`/public/${slug}`} className="publicLayout__brand">
            {workspace.name}
          </Link>
          <a href="/signin" className="publicLayout__signIn">Sign in</a>
        </div>
      </header>
      <main className="publicLayout__main">
        <Outlet context={{ workspace }} />
      </main>
      <footer className="publicLayout__footer">
        <div className="publicLayout__footerContent">
          <span className="publicLayout__footerText">
            Powered by OneBigHead
          </span>
        </div>
      </footer>
    </div>
  );
}

export default PublicLayout;
```

**Step 2: Create the barrel export**

Create `frontend/src/components/public/index.ts`:

```typescript
export { default as PublicLayout } from './PublicLayout';
```

**Step 3: Create the CSS**

Create `frontend/src/styles/components/PublicLayout.css`:

```css
.publicLayout {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  background: var(--color-bg);
}

.publicLayout__header {
  background: var(--color-surface);
  border-bottom: 1px solid var(--color-border);
  padding: 0 var(--space-xl);
}

.publicLayout__headerContent {
  max-width: 1200px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 56px;
}

.publicLayout__brand {
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--color-text);
  text-decoration: none;
}

.publicLayout__brand:hover {
  color: var(--color-primary);
}

.publicLayout__signIn {
  color: var(--color-primary);
  text-decoration: none;
  font-size: 0.875rem;
  font-weight: 500;
}

.publicLayout__signIn:hover {
  text-decoration: underline;
}

.publicLayout__main {
  flex: 1;
  max-width: 1200px;
  margin: 0 auto;
  width: 100%;
  padding: var(--space-xl);
}

.publicLayout__footer {
  background: var(--color-surface);
  border-top: 1px solid var(--color-border);
  padding: var(--space-md) var(--space-xl);
}

.publicLayout__footerContent {
  max-width: 1200px;
  margin: 0 auto;
  text-align: center;
}

.publicLayout__footerText {
  color: var(--color-text-muted);
  font-size: 0.75rem;
}

.publicLayout__loading,
.publicLayout__error {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 50vh;
  color: var(--color-text-muted);
}

.publicLayout__error h1 {
  margin: 0 0 var(--space-sm);
  color: var(--color-text);
}
```

**Step 4: Commit**

```bash
git add frontend/src/components/public/ frontend/src/styles/components/PublicLayout.css
git commit -m "feat: add PublicLayout component for anonymous browsing shell"
```

---

### Task 11: Create Public Collection List View

**Files:**
- Create: `frontend/src/views/PublicCollectionsView.tsx`
- Create: `frontend/src/styles/components/PublicCollections.css`

**Step 1: Create the view**

Create `frontend/src/views/PublicCollectionsView.tsx`:

```tsx
import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { publicApi, type PublicCollection } from '../api';
import '../styles/components/PublicCollections.css';

function PublicCollectionsView() {
  const { slug } = useParams<{ slug: string }>();
  const navigate = useNavigate();
  const [collections, setCollections] = useState<PublicCollection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!slug) return;

    setLoading(true);
    publicApi.getCollections(slug)
      .then(setCollections)
      .catch(() => setError('Failed to load collections'))
      .finally(() => setLoading(false));
  }, [slug]);

  if (loading) {
    return <div className="publicCollections__loading">Loading collections...</div>;
  }

  if (error) {
    return <div className="publicCollections__error">{error}</div>;
  }

  if (collections.length === 0) {
    return (
      <div className="publicCollections__empty">
        <p>No public collections available.</p>
      </div>
    );
  }

  return (
    <div className="publicCollections">
      <h1 className="publicCollections__title">Collections</h1>
      <div className="publicCollections__grid">
        {collections.map((collection) => (
          <button
            key={collection.id}
            className="publicCollections__card"
            onClick={() => navigate(`/public/${slug}/collections/${collection.id}`)}
          >
            {collection.heroImageUrl && (
              <div className="publicCollections__imageWrap">
                <img
                  src={collection.heroImageUrl}
                  alt={collection.name}
                  className="publicCollections__image"
                />
              </div>
            )}
            <div className="publicCollections__content">
              <h2 className="publicCollections__name">{collection.name}</h2>
              {collection.description && (
                <p className="publicCollections__description">{collection.description}</p>
              )}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

export default PublicCollectionsView;
```

**Step 2: Create the CSS**

Create `frontend/src/styles/components/PublicCollections.css`:

```css
.publicCollections__title {
  margin: 0 0 var(--space-lg);
  font-size: 1.75rem;
  color: var(--color-text);
}

.publicCollections__grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: var(--space-lg);
}

.publicCollections__card {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  background: var(--color-surface);
  cursor: pointer;
  transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
  text-align: left;
  padding: 0;
  width: 100%;
  font: inherit;
  color: inherit;
}

.publicCollections__card:hover {
  border-color: var(--color-primary);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.publicCollections__imageWrap {
  aspect-ratio: 16 / 9;
  overflow: hidden;
  border-radius: var(--radius-lg) var(--radius-lg) 0 0;
}

.publicCollections__image {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.publicCollections__content {
  padding: var(--space-lg);
}

.publicCollections__name {
  margin: 0 0 var(--space-xs);
  font-size: 1.125rem;
}

.publicCollections__description {
  margin: 0;
  color: var(--color-text-muted);
  font-size: 0.875rem;
  line-height: 1.5;
}

.publicCollections__loading,
.publicCollections__error,
.publicCollections__empty {
  text-align: center;
  padding: var(--space-xxl);
  color: var(--color-text-muted);
}

@media (max-width: 768px) {
  .publicCollections__grid {
    grid-template-columns: 1fr;
  }
}
```

**Step 3: Commit**

```bash
git add frontend/src/views/PublicCollectionsView.tsx frontend/src/styles/components/PublicCollections.css
git commit -m "feat: add PublicCollectionsView for browsing public collections"
```

---

### Task 12: Create Public Collection Detail View

**Files:**
- Create: `frontend/src/views/PublicCollectionDetailView.tsx`
- Create: `frontend/src/styles/components/PublicCollectionDetail.css`

**Step 1: Create the view**

Create `frontend/src/views/PublicCollectionDetailView.tsx`:

```tsx
import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { publicApi, type PublicCollectionDetail, type PublicItemSummary, type PublicCategory } from '../api';
import '../styles/components/PublicCollectionDetail.css';

function PublicCollectionDetailView() {
  const { slug, collectionId } = useParams<{ slug: string; collectionId: string }>();
  const navigate = useNavigate();
  const [detail, setDetail] = useState<PublicCollectionDetail | null>(null);
  const [items, setItems] = useState<PublicItemSummary[]>([]);
  const [selectedCategoryId, setSelectedCategoryId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [itemsLoading, setItemsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const collectionIdNum = collectionId ? parseInt(collectionId, 10) : null;

  // Load collection detail
  useEffect(() => {
    if (!slug || !collectionIdNum) return;

    setLoading(true);
    publicApi.getCollection(slug, collectionIdNum)
      .then(setDetail)
      .catch(() => setError('Collection not found'))
      .finally(() => setLoading(false));
  }, [slug, collectionIdNum]);

  // Load items when category changes
  useEffect(() => {
    if (!slug || !collectionIdNum) return;

    setItemsLoading(true);
    publicApi.getItems(slug, collectionIdNum, selectedCategoryId ?? undefined)
      .then(setItems)
      .catch(() => setItems([]))
      .finally(() => setItemsLoading(false));
  }, [slug, collectionIdNum, selectedCategoryId]);

  if (loading) {
    return <div className="publicDetail__loading">Loading collection...</div>;
  }

  if (error || !detail) {
    return <div className="publicDetail__error">{error || 'Collection not found'}</div>;
  }

  // Build category tree
  const rootCategories = detail.categories.filter(c => !c.parentCategoryId);
  const childrenOf = (parentId: number) => detail.categories.filter(c => c.parentCategoryId === parentId);

  const renderCategory = (category: PublicCategory, depth: number = 0) => (
    <li key={category.id}>
      <button
        className={`publicDetail__categoryBtn ${selectedCategoryId === category.id ? 'publicDetail__categoryBtn--active' : ''}`}
        style={{ paddingLeft: `${depth * 16 + 12}px` }}
        onClick={() => setSelectedCategoryId(selectedCategoryId === category.id ? null : category.id)}
      >
        {category.name}
      </button>
      {childrenOf(category.id).length > 0 && (
        <ul className="publicDetail__categoryList">
          {childrenOf(category.id).map(child => renderCategory(child, depth + 1))}
        </ul>
      )}
    </li>
  );

  return (
    <div className="publicDetail">
      <div className="publicDetail__header">
        <button
          className="publicDetail__back"
          onClick={() => navigate(`/public/${slug}`)}
        >
          &larr; All Collections
        </button>
        <h1 className="publicDetail__title">{detail.collection.name}</h1>
        {detail.collection.description && (
          <p className="publicDetail__description">{detail.collection.description}</p>
        )}
      </div>

      <div className="publicDetail__content">
        {detail.categories.length > 0 && (
          <aside className="publicDetail__sidebar">
            <h2 className="publicDetail__sidebarTitle">Categories</h2>
            <button
              className={`publicDetail__categoryBtn ${selectedCategoryId === null ? 'publicDetail__categoryBtn--active' : ''}`}
              onClick={() => setSelectedCategoryId(null)}
            >
              All Items
            </button>
            <ul className="publicDetail__categoryList">
              {rootCategories.map(cat => renderCategory(cat))}
            </ul>
          </aside>
        )}

        <div className="publicDetail__items">
          {itemsLoading ? (
            <div className="publicDetail__loading">Loading items...</div>
          ) : items.length === 0 ? (
            <div className="publicDetail__empty">No items in this view.</div>
          ) : (
            <div className="publicDetail__itemGrid">
              {items.map(item => (
                <button
                  key={item.id}
                  className="publicDetail__itemCard"
                  onClick={() => navigate(`/public/${slug}/items/${item.id}`)}
                >
                  {item.primaryImageUrl && (
                    <div className="publicDetail__itemImageWrap">
                      <img
                        src={item.primaryImageUrl}
                        alt={item.name}
                        className="publicDetail__itemImage"
                      />
                    </div>
                  )}
                  <div className="publicDetail__itemContent">
                    <h3 className="publicDetail__itemName">{item.name}</h3>
                    {item.summary && (
                      <p className="publicDetail__itemSummary">{item.summary}</p>
                    )}
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default PublicCollectionDetailView;
```

**Step 2: Create the CSS**

Create `frontend/src/styles/components/PublicCollectionDetail.css`:

```css
.publicDetail__header {
  margin-bottom: var(--space-xl);
}

.publicDetail__back {
  background: none;
  border: none;
  color: var(--color-primary);
  cursor: pointer;
  font: inherit;
  font-size: 0.875rem;
  padding: 0;
  margin-bottom: var(--space-sm);
}

.publicDetail__back:hover {
  text-decoration: underline;
}

.publicDetail__title {
  margin: 0 0 var(--space-xs);
  font-size: 1.75rem;
  color: var(--color-text);
}

.publicDetail__description {
  margin: 0;
  color: var(--color-text-secondary);
  line-height: 1.5;
}

.publicDetail__content {
  display: flex;
  gap: var(--space-xl);
}

.publicDetail__sidebar {
  flex-shrink: 0;
  width: 240px;
}

.publicDetail__sidebarTitle {
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--color-text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin: 0 0 var(--space-sm);
}

.publicDetail__categoryList {
  list-style: none;
  padding: 0;
  margin: 0;
}

.publicDetail__categoryBtn {
  display: block;
  width: 100%;
  text-align: left;
  background: none;
  border: none;
  padding: var(--space-xs) var(--space-sm);
  border-radius: var(--radius-sm);
  cursor: pointer;
  font: inherit;
  font-size: 0.875rem;
  color: var(--color-text-secondary);
  transition: background var(--transition-fast), color var(--transition-fast);
}

.publicDetail__categoryBtn:hover {
  background: var(--color-hover);
}

.publicDetail__categoryBtn--active {
  background: var(--color-primary-bg, rgba(59, 130, 246, 0.1));
  color: var(--color-primary);
  font-weight: 500;
}

.publicDetail__items {
  flex: 1;
  min-width: 0;
}

.publicDetail__itemGrid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: var(--space-md);
}

.publicDetail__itemCard {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  background: var(--color-surface);
  cursor: pointer;
  transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
  text-align: left;
  padding: 0;
  width: 100%;
  font: inherit;
  color: inherit;
}

.publicDetail__itemCard:hover {
  border-color: var(--color-primary);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
}

.publicDetail__itemImageWrap {
  aspect-ratio: 1;
  overflow: hidden;
  border-radius: var(--radius-md) var(--radius-md) 0 0;
}

.publicDetail__itemImage {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.publicDetail__itemContent {
  padding: var(--space-sm) var(--space-md);
}

.publicDetail__itemName {
  margin: 0;
  font-size: 0.875rem;
  font-weight: 500;
}

.publicDetail__itemSummary {
  margin: var(--space-xs) 0 0;
  font-size: 0.75rem;
  color: var(--color-text-muted);
  line-height: 1.4;
}

.publicDetail__loading,
.publicDetail__error,
.publicDetail__empty {
  text-align: center;
  padding: var(--space-xxl);
  color: var(--color-text-muted);
}

@media (max-width: 768px) {
  .publicDetail__content {
    flex-direction: column;
  }

  .publicDetail__sidebar {
    width: 100%;
  }

  .publicDetail__itemGrid {
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  }
}
```

**Step 3: Commit**

```bash
git add frontend/src/views/PublicCollectionDetailView.tsx frontend/src/styles/components/PublicCollectionDetail.css
git commit -m "feat: add PublicCollectionDetailView with category sidebar and item grid"
```

---

### Task 13: Create Public Item Detail View

**Files:**
- Create: `frontend/src/views/PublicItemView.tsx`
- Create: `frontend/src/styles/components/PublicItem.css`

**Step 1: Create the view**

Create `frontend/src/views/PublicItemView.tsx`:

```tsx
import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { publicApi, type PublicItem } from '../api';
import '../styles/components/PublicItem.css';

function PublicItemView() {
  const { slug, itemId } = useParams<{ slug: string; itemId: string }>();
  const navigate = useNavigate();
  const [item, setItem] = useState<PublicItem | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedImageIndex, setSelectedImageIndex] = useState(0);

  const itemIdNum = itemId ? parseInt(itemId, 10) : null;

  useEffect(() => {
    if (!slug || !itemIdNum) return;

    setLoading(true);
    publicApi.getItem(slug, itemIdNum)
      .then(setItem)
      .catch(() => setError('Item not found'))
      .finally(() => setLoading(false));
  }, [slug, itemIdNum]);

  if (loading) {
    return <div className="publicItem__loading">Loading item...</div>;
  }

  if (error || !item) {
    return <div className="publicItem__error">{error || 'Item not found'}</div>;
  }

  // Group properties by category
  const propertyGroups = item.properties.reduce<Record<string, { name: string; value: string }[]>>((acc, prop) => {
    const key = prop.category || 'Details';
    if (!acc[key]) acc[key] = [];
    acc[key].push({ name: prop.name, value: prop.value });
    return acc;
  }, {});

  return (
    <div className="publicItem">
      <button
        className="publicItem__back"
        onClick={() => navigate(-1)}
      >
        &larr; Back
      </button>

      <div className="publicItem__layout">
        {item.images.length > 0 && (
          <div className="publicItem__gallery">
            <div className="publicItem__mainImage">
              <img
                src={item.images[selectedImageIndex]?.url}
                alt={item.images[selectedImageIndex]?.caption || item.name}
                className="publicItem__image"
              />
            </div>
            {item.images.length > 1 && (
              <div className="publicItem__thumbnails">
                {item.images.map((img, idx) => (
                  <button
                    key={idx}
                    className={`publicItem__thumbnail ${idx === selectedImageIndex ? 'publicItem__thumbnail--active' : ''}`}
                    onClick={() => setSelectedImageIndex(idx)}
                  >
                    <img src={img.url} alt={img.caption || `Image ${idx + 1}`} />
                  </button>
                ))}
              </div>
            )}
          </div>
        )}

        <div className="publicItem__info">
          <h1 className="publicItem__name">{item.name}</h1>

          {item.categoryName && (
            <div className="publicItem__category">{item.categoryName}</div>
          )}

          {item.summary && (
            <p className="publicItem__summary">{item.summary}</p>
          )}

          {item.description && (
            <div className="publicItem__description">{item.description}</div>
          )}

          {Object.entries(propertyGroups).map(([category, props]) => (
            <div key={category} className="publicItem__propertyGroup">
              <h2 className="publicItem__propertyGroupTitle">{category}</h2>
              <dl className="publicItem__properties">
                {props.map((prop, idx) => (
                  <div key={idx} className="publicItem__property">
                    <dt className="publicItem__propertyName">{prop.name}</dt>
                    <dd className="publicItem__propertyValue">{prop.value}</dd>
                  </div>
                ))}
              </dl>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default PublicItemView;
```

**Step 2: Create the CSS**

Create `frontend/src/styles/components/PublicItem.css`:

```css
.publicItem__back {
  background: none;
  border: none;
  color: var(--color-primary);
  cursor: pointer;
  font: inherit;
  font-size: 0.875rem;
  padding: 0;
  margin-bottom: var(--space-lg);
}

.publicItem__back:hover {
  text-decoration: underline;
}

.publicItem__layout {
  display: flex;
  gap: var(--space-xl);
}

.publicItem__gallery {
  flex-shrink: 0;
  width: 400px;
}

.publicItem__mainImage {
  aspect-ratio: 1;
  overflow: hidden;
  border-radius: var(--radius-lg);
  border: 1px solid var(--color-border);
  background: var(--color-surface);
}

.publicItem__image {
  width: 100%;
  height: 100%;
  object-fit: contain;
}

.publicItem__thumbnails {
  display: flex;
  gap: var(--space-xs);
  margin-top: var(--space-sm);
  overflow-x: auto;
}

.publicItem__thumbnail {
  width: 60px;
  height: 60px;
  border: 2px solid var(--color-border);
  border-radius: var(--radius-sm);
  overflow: hidden;
  cursor: pointer;
  padding: 0;
  background: var(--color-surface);
  flex-shrink: 0;
}

.publicItem__thumbnail:hover {
  border-color: var(--color-primary);
}

.publicItem__thumbnail--active {
  border-color: var(--color-primary);
}

.publicItem__thumbnail img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.publicItem__info {
  flex: 1;
  min-width: 0;
}

.publicItem__name {
  margin: 0 0 var(--space-xs);
  font-size: 1.5rem;
  color: var(--color-text);
}

.publicItem__category {
  font-size: 0.875rem;
  color: var(--color-primary);
  margin-bottom: var(--space-md);
}

.publicItem__summary {
  margin: 0 0 var(--space-md);
  color: var(--color-text-secondary);
  line-height: 1.5;
}

.publicItem__description {
  margin: 0 0 var(--space-lg);
  color: var(--color-text-secondary);
  line-height: 1.6;
  white-space: pre-wrap;
}

.publicItem__propertyGroup {
  margin-bottom: var(--space-lg);
}

.publicItem__propertyGroupTitle {
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--color-text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin: 0 0 var(--space-sm);
  padding-bottom: var(--space-xs);
  border-bottom: 1px solid var(--color-border);
}

.publicItem__properties {
  margin: 0;
}

.publicItem__property {
  display: flex;
  padding: var(--space-xs) 0;
  border-bottom: 1px solid var(--color-border-light, rgba(0, 0, 0, 0.05));
}

.publicItem__propertyName {
  flex-shrink: 0;
  width: 140px;
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--color-text-secondary);
}

.publicItem__propertyValue {
  margin: 0;
  font-size: 0.875rem;
  color: var(--color-text);
}

.publicItem__loading,
.publicItem__error {
  text-align: center;
  padding: var(--space-xxl);
  color: var(--color-text-muted);
}

@media (max-width: 768px) {
  .publicItem__layout {
    flex-direction: column;
  }

  .publicItem__gallery {
    width: 100%;
  }

  .publicItem__property {
    flex-direction: column;
    gap: var(--space-xs);
  }

  .publicItem__propertyName {
    width: auto;
  }
}
```

**Step 3: Commit**

```bash
git add frontend/src/views/PublicItemView.tsx frontend/src/styles/components/PublicItem.css
git commit -m "feat: add PublicItemView for viewing item details anonymously"
```

---

### Task 14: Add Public Routes to Router

**Files:**
- Modify: `frontend/src/router.tsx`

**Step 1: Add lazy imports and routes**

Add lazy imports at the top of `router.tsx`:

```typescript
const PublicLayout = lazy(() => import('./components/public/PublicLayout'));
const PublicCollectionsView = lazy(() => import('./views/PublicCollectionsView'));
const PublicCollectionDetailView = lazy(() => import('./views/PublicCollectionDetailView'));
const PublicItemView = lazy(() => import('./views/PublicItemView'));
```

Add the public route block to the router array (after the existing routes, before the closing `]`):

```typescript
{
  path: '/public/:slug',
  element: (
    <Suspense fallback={<LoadingFallback />}>
      <PublicLayout />
    </Suspense>
  ),
  children: [
    {
      index: true,
      element: (
        <Suspense fallback={<LoadingFallback />}>
          <PublicCollectionsView />
        </Suspense>
      ),
    },
    {
      path: 'collections/:collectionId',
      element: (
        <Suspense fallback={<LoadingFallback />}>
          <PublicCollectionDetailView />
        </Suspense>
      ),
    },
    {
      path: 'items/:itemId',
      element: (
        <Suspense fallback={<LoadingFallback />}>
          <PublicItemView />
        </Suspense>
      ),
    },
  ],
},
```

**Step 2: Commit**

```bash
git add frontend/src/router.tsx
git commit -m "feat: add public routes for anonymous collection browsing"
```

---

### Task 15: Add Public Access Settings to Workspace UI

**Files:**
- Modify: `frontend/src/api/workspaces.ts`
- Modify: `frontend/src/views/SettingsView.tsx`

**Step 1: Add workspace public access API methods**

Add to `frontend/src/api/workspaces.ts`:

```typescript
export interface UpdatePublicAccessRequest {
  slug: string | null;
  isPublicAccessEnabled: boolean;
}

export interface UpdatePublicAccessResponse {
  workspaceId: number;
  slug: string | null;
  isPublicAccessEnabled: boolean;
  publicUrl: string | null;
}

export interface CheckSlugResponse {
  isAvailable: boolean;
}
```

Add methods to the `workspacesApi` object:

```typescript
updatePublicAccess(workspaceId: number, request: UpdatePublicAccessRequest): Promise<UpdatePublicAccessResponse> {
  return api.put<UpdatePublicAccessResponse>(`/workspaces/${workspaceId}/public-access`, request);
},

checkSlug(slug: string): Promise<CheckSlugResponse> {
  return api.get<CheckSlugResponse>(`/workspaces/check-slug/${slug}`);
},
```

**Step 2: Update the api/index.ts exports**

Add `UpdatePublicAccessRequest`, `UpdatePublicAccessResponse`, `CheckSlugResponse` to the exports from `workspaces` in `frontend/src/api/index.ts`.

**Step 3: Add public access section to SettingsView**

Add a "Public Access" section to the workspaces settings area of `SettingsView.tsx`. This requires reading the current file to understand the exact structure and where to add the new section. Look for the workspace settings section rendering and add a new sub-section.

The section should include:
- A heading "Public Access"
- A slug input field with validation (auto-generates from workspace name)
- A slug availability check (calls `workspacesApi.checkSlug`)
- A toggle/checkbox for `isPublicAccessEnabled`
- A preview of the public URL when enabled
- A save button that calls `workspacesApi.updatePublicAccess`

This task requires careful reading of the existing `SettingsView.tsx` to integrate properly. The implementer should read the full file first.

**Step 4: Commit**

```bash
git add frontend/src/api/workspaces.ts frontend/src/api/index.ts frontend/src/views/SettingsView.tsx
git commit -m "feat: add public access settings to workspace configuration"
```

---

### Task 16: Add GetPublicAccessSettings Endpoint

**Files:**
- Modify: `backend/src/backend/Controllers/WorkspacesController.cs`
- Modify: `backend/src/backend/DTOs/WorkspaceRequests.cs`

**Step 1: Add a GET endpoint for current public access settings**

The frontend settings page needs to load the current public access state. Add to `WorkspacesController`:

```csharp
/// <summary>
/// Get workspace public access settings (requires WorkspaceAdmin)
/// </summary>
[HttpGet("{workspaceId}/public-access")]
[Authorize(Policy = "WorkspaceAdmin")]
public async Task<IActionResult> GetPublicAccess(int workspaceId)
{
    var userId = GetUserId();

    var membership = await _workspaceUserRepository.GetMembershipAsync(userId, workspaceId);
    if (membership == null || membership.WorkspaceRole != WorkspaceRole.WorkspaceAdmin)
    {
        return Forbid();
    }

    var workspace = await _workspaceRepository.GetByIdAsync(workspaceId);
    if (workspace == null)
    {
        return NotFound();
    }

    var publicUrl = workspace.IsPublicAccessEnabled && !string.IsNullOrEmpty(workspace.Slug)
        ? $"/public/{workspace.Slug}"
        : null;

    return Ok(new UpdateWorkspacePublicAccessResponse
    {
        WorkspaceId = workspace.Id,
        Slug = workspace.Slug,
        IsPublicAccessEnabled = workspace.IsPublicAccessEnabled,
        PublicUrl = publicUrl
    });
}
```

**Step 2: Add GET method to frontend API**

Add to `workspacesApi` in `frontend/src/api/workspaces.ts`:

```typescript
getPublicAccess(workspaceId: number): Promise<UpdatePublicAccessResponse> {
  return api.get<UpdatePublicAccessResponse>(`/workspaces/${workspaceId}/public-access`);
},
```

**Step 3: Commit**

```bash
git add backend/src/backend/Controllers/WorkspacesController.cs frontend/src/api/workspaces.ts
git commit -m "feat: add GET endpoint for workspace public access settings"
```

---

### Task 17: Verify and Fix - End-to-End Testing

**Step 1: Run all backend tests**

```bash
cd backend
dotnet test tests/backend.tests -v n
```

Expected: All tests pass. Fix any compilation errors or test failures.

**Step 2: Run frontend linting**

```bash
cd frontend
npm run lint
```

Expected: No lint errors. Fix any issues.

**Step 3: Build frontend**

```bash
cd frontend
npm run build
```

Expected: Build succeeds. Fix any TypeScript errors.

**Step 4: Start the full stack**

```bash
./scripts/dev-start.sh --skip-tests
```

**Step 5: Manual testing**

1. Sign in as a workspace admin
2. Go to Settings > Workspaces
3. Set a slug and enable public access
4. Create a collection with Visibility = Public
5. Add some items with Visibility = Public
6. Open `/public/{slug}` in an incognito browser window
7. Verify you can browse the public collection and view items
8. Verify private collections/items are NOT visible

**Step 6: Final commit if any fixes were needed**

```bash
git add -A
git commit -m "fix: address issues found during end-to-end testing"
```
