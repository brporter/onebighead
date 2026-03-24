using backend.DTOs;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/workspaces/{workspaceId}")]
[Authorize]
public class PublishController : ApiControllerBase
{
    private readonly IVisibilityService _visibilityService;
    private readonly IItemRepository _itemRepository;
    private readonly ICategoryRepository _categoryRepository;
    private readonly ICollectionRepository _collectionRepository;
    private readonly IWorkspaceRepository _workspaceRepository;

    public PublishController(
        IVisibilityService visibilityService,
        IItemRepository itemRepository,
        ICategoryRepository categoryRepository,
        ICollectionRepository collectionRepository,
        IWorkspaceRepository workspaceRepository)
    {
        _visibilityService = visibilityService;
        _itemRepository = itemRepository;
        _categoryRepository = categoryRepository;
        _collectionRepository = collectionRepository;
        _workspaceRepository = workspaceRepository;
    }

    [HttpPost("items/{itemId}/publish")]
    public async Task<IActionResult> PublishItem(int workspaceId, int itemId)
    {
        var wsId = GetWorkspaceId();
        if (wsId != workspaceId) return Forbid();

        var item = await _itemRepository.GetByIdAsync(itemId, workspaceId);
        if (item == null) return NotFound(new { message = "Item not found" });

        var collection = await _collectionRepository.GetByIdAsync(item.CollectionId, workspaceId);
        if (collection == null) return NotFound(new { message = "Collection not found" });

        Category? category = null;
        if (item.CategoryId.HasValue)
        {
            category = await _categoryRepository.GetByIdAsync(item.CategoryId.Value, workspaceId);
        }

        var workspace = await _workspaceRepository.GetByIdAsync(workspaceId);
        if (workspace == null) return NotFound(new { message = "Workspace not found" });

        var result = _visibilityService.PublishItem(item, collection, category);

        // Persist changes
        await _itemRepository.UpdateAsync(itemId, item, workspaceId);
        await _collectionRepository.UpdateAsync(collection.Id, collection, workspaceId);
        if (category != null)
        {
            await _categoryRepository.UpdateAsync(category.Id, category, workspaceId);
        }

        return Ok(MapToPublishResponse(result, _visibilityService.RequiresSlugSetup(workspace)));
    }

    [HttpPost("items/{itemId}/unpublish")]
    public async Task<IActionResult> UnpublishItem(int workspaceId, int itemId)
    {
        var wsId = GetWorkspaceId();
        if (wsId != workspaceId) return Forbid();

        var item = await _itemRepository.GetByIdAsync(itemId, workspaceId);
        if (item == null) return NotFound(new { message = "Item not found" });

        _visibilityService.UnpublishEntity(item);
        await _itemRepository.UpdateAsync(itemId, item, workspaceId);

        return Ok(new UnpublishResponse
        {
            Unpublished = new backend.DTOs.PublishedEntityInfo
            {
                Type = "item",
                Id = item.Id ?? 0,
                Name = item.Name
            },
            AffectedPublicItems = 0,
            AffectedPublicCategories = 0
        });
    }

    [HttpPost("categories/{categoryId}/publish")]
    public async Task<IActionResult> PublishCategory(int workspaceId, int categoryId, [FromBody] PublishCategoryRequest request)
    {
        var wsId = GetWorkspaceId();
        if (wsId != workspaceId) return Forbid();

        var category = await _categoryRepository.GetByIdAsync(categoryId, workspaceId);
        if (category == null) return NotFound(new { message = "Category not found" });

        var collection = await _collectionRepository.GetByIdAsync(category.CollectionId, workspaceId);
        if (collection == null) return NotFound(new { message = "Collection not found" });

        var allCategories = (await _categoryRepository.GetByCollectionAsync(collection.Id, workspaceId)).ToList();
        var categoryItems = (await _itemRepository.GetByCollectionIdAsync(collection.Id, workspaceId)).ToList();

        var workspace = await _workspaceRepository.GetByIdAsync(workspaceId);
        if (workspace == null) return NotFound(new { message = "Workspace not found" });

        var result = _visibilityService.PublishCategory(category, collection, categoryItems, allCategories, request.IncludeChildren);

        // Persist changes
        await _collectionRepository.UpdateAsync(collection.Id, collection, workspaceId);
        foreach (var cat in allCategories)
        {
            await _categoryRepository.UpdateAsync(cat.Id, cat, workspaceId);
        }
        foreach (var item in categoryItems)
        {
            await _itemRepository.UpdateAsync(item.Id ?? 0, item, workspaceId);
        }

        return Ok(MapToPublishResponse(result, _visibilityService.RequiresSlugSetup(workspace)));
    }

    [HttpPost("categories/{categoryId}/unpublish")]
    public async Task<IActionResult> UnpublishCategory(int workspaceId, int categoryId)
    {
        var wsId = GetWorkspaceId();
        if (wsId != workspaceId) return Forbid();

        var category = await _categoryRepository.GetByIdAsync(categoryId, workspaceId);
        if (category == null) return NotFound(new { message = "Category not found" });

        var collection = await _collectionRepository.GetByIdAsync(category.CollectionId, workspaceId);
        if (collection == null) return NotFound(new { message = "Collection not found" });

        var allCategories = (await _categoryRepository.GetByCollectionAsync(collection.Id, workspaceId)).ToList();
        var categoryItems = (await _itemRepository.GetByCollectionIdAsync(collection.Id, workspaceId)).ToList();

        // Get preview before unpublishing
        var preview = _visibilityService.GetUnpublishPreview(category, categoryItems, allCategories.Where(c => c.Id != categoryId), collection);

        _visibilityService.UnpublishEntity(category);
        await _categoryRepository.UpdateAsync(categoryId, category, workspaceId);

        return Ok(new UnpublishResponse
        {
            Unpublished = new backend.DTOs.PublishedEntityInfo
            {
                Type = "category",
                Id = category.Id,
                Name = category.Name
            },
            AffectedPublicItems = preview.AffectedPublicItems,
            AffectedPublicCategories = preview.AffectedPublicCategories
        });
    }

    [HttpGet("categories/{categoryId}/unpublish-preview")]
    public async Task<IActionResult> GetCategoryUnpublishPreview(int workspaceId, int categoryId)
    {
        var wsId = GetWorkspaceId();
        if (wsId != workspaceId) return Forbid();

        var category = await _categoryRepository.GetByIdAsync(categoryId, workspaceId);
        if (category == null) return NotFound(new { message = "Category not found" });

        var collection = await _collectionRepository.GetByIdAsync(category.CollectionId, workspaceId);
        if (collection == null) return NotFound(new { message = "Collection not found" });

        var allCategories = (await _categoryRepository.GetByCollectionAsync(collection.Id, workspaceId)).ToList();
        var categoryItems = (await _itemRepository.GetByCollectionIdAsync(collection.Id, workspaceId)).ToList();

        var preview = _visibilityService.GetUnpublishPreview(category, categoryItems, allCategories.Where(c => c.Id != categoryId), collection);

        return Ok(new UnpublishPreviewResponse
        {
            AffectedPublicItems = preview.AffectedPublicItems,
            AffectedPublicCategories = preview.AffectedPublicCategories
        });
    }

    [HttpPost("collections/{collectionId}/publish")]
    public async Task<IActionResult> PublishCollection(int workspaceId, int collectionId, [FromBody] PublishCollectionRequest request)
    {
        var wsId = GetWorkspaceId();
        if (wsId != workspaceId) return Forbid();

        var collection = await _collectionRepository.GetByIdAsync(collectionId, workspaceId);
        if (collection == null) return NotFound(new { message = "Collection not found" });

        var categories = (await _categoryRepository.GetByCollectionAsync(collectionId, workspaceId)).ToList();
        var items = (await _itemRepository.GetByCollectionIdAsync(collectionId, workspaceId)).ToList();

        var workspace = await _workspaceRepository.GetByIdAsync(workspaceId);
        if (workspace == null) return NotFound(new { message = "Workspace not found" });

        var result = _visibilityService.PublishCollection(collection, categories, items, request.IncludeChildren);

        // Persist changes
        await _collectionRepository.UpdateAsync(collectionId, collection, workspaceId);
        foreach (var cat in categories)
        {
            await _categoryRepository.UpdateAsync(cat.Id, cat, workspaceId);
        }
        foreach (var item in items)
        {
            await _itemRepository.UpdateAsync(item.Id ?? 0, item, workspaceId);
        }

        return Ok(MapToPublishResponse(result, _visibilityService.RequiresSlugSetup(workspace)));
    }

    [HttpPost("collections/{collectionId}/unpublish")]
    public async Task<IActionResult> UnpublishCollection(int workspaceId, int collectionId)
    {
        var wsId = GetWorkspaceId();
        if (wsId != workspaceId) return Forbid();

        var collection = await _collectionRepository.GetByIdAsync(collectionId, workspaceId);
        if (collection == null) return NotFound(new { message = "Collection not found" });

        var categories = (await _categoryRepository.GetByCollectionAsync(collectionId, workspaceId)).ToList();
        var items = (await _itemRepository.GetByCollectionIdAsync(collectionId, workspaceId)).ToList();

        // Get preview before unpublishing
        var preview = _visibilityService.GetUnpublishPreviewForCollection(collection, categories, items);

        _visibilityService.UnpublishEntity(collection);
        await _collectionRepository.UpdateAsync(collectionId, collection, workspaceId);

        return Ok(new UnpublishResponse
        {
            Unpublished = new backend.DTOs.PublishedEntityInfo
            {
                Type = "collection",
                Id = collection.Id,
                Name = collection.Name
            },
            AffectedPublicItems = preview.AffectedPublicItems,
            AffectedPublicCategories = preview.AffectedPublicCategories
        });
    }

    [HttpGet("collections/{collectionId}/unpublish-preview")]
    public async Task<IActionResult> GetCollectionUnpublishPreview(int workspaceId, int collectionId)
    {
        var wsId = GetWorkspaceId();
        if (wsId != workspaceId) return Forbid();

        var collection = await _collectionRepository.GetByIdAsync(collectionId, workspaceId);
        if (collection == null) return NotFound(new { message = "Collection not found" });

        var categories = (await _categoryRepository.GetByCollectionAsync(collectionId, workspaceId)).ToList();
        var items = (await _itemRepository.GetByCollectionIdAsync(collectionId, workspaceId)).ToList();

        var preview = _visibilityService.GetUnpublishPreviewForCollection(collection, categories, items);

        return Ok(new UnpublishPreviewResponse
        {
            AffectedPublicItems = preview.AffectedPublicItems,
            AffectedPublicCategories = preview.AffectedPublicCategories
        });
    }

    [HttpPost("items/bulk-publish")]
    public async Task<IActionResult> BulkPublishItems(int workspaceId, [FromBody] BulkPublishRequest request)
    {
        var wsId = GetWorkspaceId();
        if (wsId != workspaceId) return Forbid();

        if (request.ItemIds == null || request.ItemIds.Count == 0)
            return BadRequest(new { message = "ItemIds must not be empty" });

        var workspace = await _workspaceRepository.GetByIdAsync(workspaceId);
        if (workspace == null) return NotFound(new { message = "Workspace not found" });

        var allPromoted = new List<backend.DTOs.PublishedEntityInfo>();
        int publishedCount = 0;
        var promotedCollectionIds = new HashSet<int>();
        var promotedCategoryIds = new HashSet<int>();

        foreach (var itemId in request.ItemIds)
        {
            var item = await _itemRepository.GetByIdAsync(itemId, workspaceId);
            if (item == null) continue;

            var collection = await _collectionRepository.GetByIdAsync(item.CollectionId, workspaceId);
            if (collection == null) continue;

            Category? category = null;
            if (item.CategoryId.HasValue)
            {
                category = await _categoryRepository.GetByIdAsync(item.CategoryId.Value, workspaceId);
            }

            var result = _visibilityService.PublishItem(item, collection, category);
            publishedCount++;

            await _itemRepository.UpdateAsync(itemId, item, workspaceId);
            await _collectionRepository.UpdateAsync(collection.Id, collection, workspaceId);
            if (category != null)
            {
                await _categoryRepository.UpdateAsync(category.Id, category, workspaceId);
            }

            // Track promoted entities to avoid duplicates
            foreach (var promoted in result.Promoted)
            {
                bool alreadyTracked = promoted.Type switch
                {
                    "collection" => !promotedCollectionIds.Add(promoted.Id),
                    "category" => !promotedCategoryIds.Add(promoted.Id),
                    _ => false
                };
                if (!alreadyTracked)
                {
                    allPromoted.Add(MapToPublishedEntityInfo(promoted));
                }
            }
        }

        return Ok(new BulkPublishResponse
        {
            PublishedCount = publishedCount,
            Promoted = allPromoted,
            RequiresSlugSetup = _visibilityService.RequiresSlugSetup(workspace)
        });
    }

    [HttpPost("items/bulk-unpublish")]
    public async Task<IActionResult> BulkUnpublishItems(int workspaceId, [FromBody] BulkUnpublishRequest request)
    {
        var wsId = GetWorkspaceId();
        if (wsId != workspaceId) return Forbid();

        if (request.ItemIds == null || request.ItemIds.Count == 0)
            return BadRequest(new { message = "ItemIds must not be empty" });

        int unpublishedCount = 0;

        foreach (var itemId in request.ItemIds)
        {
            var item = await _itemRepository.GetByIdAsync(itemId, workspaceId);
            if (item == null) continue;

            _visibilityService.UnpublishEntity(item);
            await _itemRepository.UpdateAsync(itemId, item, workspaceId);
            unpublishedCount++;
        }

        return Ok(new BulkUnpublishResponse
        {
            UnpublishedCount = unpublishedCount
        });
    }

    private static PublishResponse MapToPublishResponse(PublishResult result, bool requiresSlugSetup)
    {
        return new PublishResponse
        {
            Published = MapToPublishedEntityInfo(result.Published),
            Promoted = result.Promoted.Select(MapToPublishedEntityInfo).ToList(),
            ChildrenPublished = result.ChildrenPublished,
            RequiresSlugSetup = requiresSlugSetup
        };
    }

    private static backend.DTOs.PublishedEntityInfo MapToPublishedEntityInfo(OneBigHead.Server.Services.PublishedEntityInfo source)
    {
        return new backend.DTOs.PublishedEntityInfo
        {
            Type = source.Type,
            Id = source.Id,
            Name = source.Name
        };
    }
}
