using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using OneBigHead.Server.Services.BulkUpdate;
using OneBigHead.Server.Utilities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ItemsController : ApiControllerBase
{
    private readonly IItemRepository _itemRepository;
    private readonly ICategoryRepository _categoryRepository;
    private readonly ICollectionRepository _collectionRepository;
    private readonly IPublishManagerService _publishManagerService;
    private readonly IBulkUpdateQueue _bulkUpdateQueue;
    private readonly IWorkspaceStatisticsRepository _statisticsRepository;
    private readonly ICollectionStatisticsRepository _collectionStatisticsRepository;

    public ItemsController(
        IItemRepository itemRepository,
        ICategoryRepository categoryRepository,
        ICollectionRepository collectionRepository,
        IPublishManagerService publishManagerService,
        IBulkUpdateQueue bulkUpdateQueue,
        IWorkspaceStatisticsRepository statisticsRepository,
        ICollectionStatisticsRepository collectionStatisticsRepository)
    {
        _itemRepository = itemRepository;
        _categoryRepository = categoryRepository;
        _collectionRepository = collectionRepository;
        _publishManagerService = publishManagerService;
        _bulkUpdateQueue = bulkUpdateQueue;
        _statisticsRepository = statisticsRepository;
        _collectionStatisticsRepository = collectionStatisticsRepository;
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<Item>>> GetItems(
        [FromQuery] int? categoryId = null,
        [FromQuery] bool includeDescendants = false,
        [FromQuery][Range(0, int.MaxValue)] int? skip = null,
        [FromQuery][Range(0, int.MaxValue)] int? take = null)
    {
        var workspaceId = GetWorkspaceId();

        IEnumerable<Item> items;
        if (categoryId == null)
        {
            items = await _itemRepository.GetAllAsync(workspaceId);
        }
        else
        {
            IEnumerable<int> categoryIds;
            if (includeDescendants)
            {
                categoryIds = await GetCategoryAndDescendantIds(categoryId.Value, workspaceId);
            }
            else
            {
                categoryIds = new[] { categoryId.Value };
            }
            items = await _itemRepository.GetByCategoryIdsAsync(categoryIds, workspaceId);
        }

        var itemList = items.ToList();
        
        // Compute effective visibility
        var collection = await _collectionRepository.GetByWorkspaceIdAsync(workspaceId);
        if (collection != null)
        {
            var allCategories = await _categoryRepository.GetAllAsync(workspaceId);
            var categoryList = allCategories.ToList();
            _publishManagerService.ComputeEffectiveVisibility(categoryList, collection);
            _publishManagerService.ComputeEffectiveVisibility(itemList, collection, categoryList);
        }
        
        // Compute ETag on full dataset BEFORE pagination for proper HTTP caching semantics
        var etag = ETagHelper.ComputeETag(itemList, i => i.Id);
        Response.Headers.ETag = etag;

        var ifNoneMatch = Request.Headers.IfNoneMatch.FirstOrDefault();
        if (!string.IsNullOrEmpty(ifNoneMatch) && ifNoneMatch == etag)
        {
            return StatusCode(StatusCodes.Status304NotModified);
        }
        
        // Apply pagination if requested (after ETag computation)
        var totalCount = itemList.Count;
        if (skip.HasValue || take.HasValue)
        {
            Response.Headers["X-Total-Count"] = totalCount.ToString();
            
            if (skip.HasValue && skip.Value > 0)
            {
                itemList = itemList.Skip(skip.Value).ToList();
            }
            if (take.HasValue && take.Value > 0)
            {
                itemList = itemList.Take(take.Value).ToList();
            }
        }

        return Ok(itemList);
    }

    private async Task<IEnumerable<int>> GetCategoryAndDescendantIds(int categoryId, int workspaceId)
    {
        var allCategories = await _categoryRepository.GetAllAsync(workspaceId);
        var categoryList = allCategories.ToList();

        var result = new HashSet<int> { categoryId };
        var queue = new Queue<int>();
        queue.Enqueue(categoryId);

        while (queue.Count > 0)
        {
            var currentId = queue.Dequeue();
            var children = categoryList.Where(c => c.ParentCategoryId == currentId);
            foreach (var child in children)
            {
                if (result.Add(child.Id))
                {
                    queue.Enqueue(child.Id);
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Loads categories for a collection with computed visibility.
    /// </summary>
    private async Task<(List<Category> Categories, Dictionary<int, Category> Lookup)> LoadCategoriesWithVisibility(
        int collectionId, int workspaceId, Collection collection)
    {
        var categories = (await _categoryRepository.GetByCollectionAsync(collectionId, workspaceId)).ToList();
        _publishManagerService.ComputeEffectiveVisibility(categories, collection);
        var lookup = categories.ToDictionary(c => c.Id);
        return (categories, lookup);
    }

    /// <summary>
    /// Validates category ID for item create/update.
    /// Returns the category if valid, or a BadRequest result if invalid.
    /// </summary>
    private (Category? Category, BadRequestObjectResult? Error) ValidateCategory(
        int? categoryId, Dictionary<int, Category> categoryLookup)
    {
        Category? category = null;

        if (categoryId.HasValue)
        {
            if (!categoryLookup.TryGetValue(categoryId.Value, out category))
            {
                return (null, BadRequest("Invalid category"));
            }
        }

        return (category, null);
    }

    /// <summary>
    /// Determines the default visibility for an item based on its parent category or collection.
    /// </summary>
    private static Visibility GetDefaultVisibility(Category? category, Collection collection)
    {
        bool parentEffectivelyPublic = category?.EffectiveIsPublic ?? collection.EffectiveIsPublic;
        return parentEffectivelyPublic ? Visibility.Public : Visibility.Private;
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<Item>> GetItem(int id)
    {
        var workspaceId = GetWorkspaceId();
        var item = await _itemRepository.GetByIdAsync(id, workspaceId);
        if (item is null)
        {
            return NotFound();
        }

        // Compute effective visibility
        var collection = await _collectionRepository.GetByWorkspaceIdAsync(workspaceId);
        if (collection != null)
        {
            var allCategories = await _categoryRepository.GetAllAsync(workspaceId);
            var categoryList = allCategories.ToList();
            _publishManagerService.ComputeEffectiveVisibility(categoryList, collection);
            var category = item.CategoryId.HasValue
                ? categoryList.FirstOrDefault(c => c.Id == item.CategoryId.Value)
                : null;
            _publishManagerService.ComputeEffectiveVisibility(item, collection, category);
        }

        return Ok(item);
    }

    [HttpPost]
    public async Task<ActionResult<Item>> CreateItem(CreateItemRequest request)
    {
        var workspaceId = GetWorkspaceId();

        // Check for active bulk update on this collection
        var activeJob = _bulkUpdateQueue.GetActiveJobForCollection(request.CollectionId, workspaceId);
        if (activeJob != null)
        {
            return Conflict("A bulk update is in progress for this collection. Please wait for it to complete.");
        }

        // Validate CollectionId belongs to workspace
        var collection = await _collectionRepository.GetByIdAsync(request.CollectionId, workspaceId);
        if (collection is null)
        {
            return BadRequest("Invalid collection");
        }

        // Load categories and validate
        var (categories, categoryLookup) = await LoadCategoriesWithVisibility(request.CollectionId, workspaceId, collection);
        var (category, error) = ValidateCategory(request.CategoryId, categoryLookup);
        if (error != null)
        {
            return error;
        }

        var item = request.ToItem(workspaceId);
        item.Visibility = GetDefaultVisibility(category, collection);
        var created = await _itemRepository.CreateAsync(item);
        return CreatedAtAction(nameof(GetItem), new { id = created.Id }, created);
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<Item>> UpdateItem(int id, UpdateItemRequest request)
    {
        var workspaceId = GetWorkspaceId();

        // Check for active bulk update on this collection
        var activeJob = _bulkUpdateQueue.GetActiveJobForCollection(request.CollectionId, workspaceId);
        if (activeJob != null)
        {
            return Conflict("A bulk update is in progress for this collection. Please wait for it to complete.");
        }

        // Validate CollectionId belongs to workspace
        var collection = await _collectionRepository.GetByIdAsync(request.CollectionId, workspaceId);
        if (collection is null)
        {
            return BadRequest("Invalid collection");
        }

        // Load categories and validate
        var (categories, categoryLookup) = await LoadCategoriesWithVisibility(request.CollectionId, workspaceId, collection);
        var (category, error) = ValidateCategory(request.CategoryId, categoryLookup);
        if (error != null)
        {
            return error;
        }

        // Preserve existing visibility - use publish/unpublish endpoints to change it
        var existingItem = await _itemRepository.GetByIdAsync(id, workspaceId);
        var item = request.ToItem(id, workspaceId);
        item.Visibility = existingItem?.Visibility ?? GetDefaultVisibility(category, collection);
        var updated = await _itemRepository.UpdateAsync(id, item, workspaceId);
        if (updated is null)
        {
            return NotFound();
        }
        return Ok(updated);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteItem(int id)
    {
        var workspaceId = GetWorkspaceId();
        var deleted = await _itemRepository.DeleteAsync(id, workspaceId);
        if (!deleted)
        {
            return NotFound();
        }
        return NoContent();
    }

    [HttpPost("{id}/view")]
    public async Task<IActionResult> RecordItemView(int id)
    {
        var workspaceId = GetWorkspaceId();
        try
        {
            await _statisticsRepository.IncrementAsync(
                workspaceId, Models.StatisticType.DailyItemView, 1,
                DateOnly.FromDateTime(DateTime.UtcNow));

            var item = await _itemRepository.GetByIdAsync(id, workspaceId);
            if (item != null)
            {
                await _collectionStatisticsRepository.IncrementItemViewAsync(item.CollectionId, id);
            }
        }
        catch
        {
            // Non-critical — don't fail the request
        }
        return NoContent();
    }
}

