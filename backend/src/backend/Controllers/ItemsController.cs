using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using OneBigHead.Server.Services.BulkUpdate;
using OneBigHead.Server.Services.Matching;
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
    private readonly IVisibilityService _visibilityService;
    private readonly IBulkUpdateQueue _bulkUpdateQueue;
    private readonly IWorkspaceStatisticsRepository _statisticsRepository;
    private readonly ICollectionStatisticsRepository _collectionStatisticsRepository;
    private readonly IMatchingService _matchingService;

    public ItemsController(
        IItemRepository itemRepository,
        ICategoryRepository categoryRepository,
        ICollectionRepository collectionRepository,
        IVisibilityService visibilityService,
        IBulkUpdateQueue bulkUpdateQueue,
        IWorkspaceStatisticsRepository statisticsRepository,
        ICollectionStatisticsRepository collectionStatisticsRepository,
        IMatchingService matchingService)
    {
        _itemRepository = itemRepository;
        _categoryRepository = categoryRepository;
        _collectionRepository = collectionRepository;
        _visibilityService = visibilityService;
        _bulkUpdateQueue = bulkUpdateQueue;
        _statisticsRepository = statisticsRepository;
        _collectionStatisticsRepository = collectionStatisticsRepository;
        _matchingService = matchingService;
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
            _visibilityService.ComputeEffectiveVisibility(categoryList, collection);
            _visibilityService.ComputeEffectiveVisibility(itemList, collection, categoryList);
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
        _visibilityService.ComputeEffectiveVisibility(categories, collection);
        var lookup = categories.ToDictionary(c => c.Id);
        return (categories, lookup);
    }

    /// <summary>
    /// Validates category ID and visibility for item create/update.
    /// Returns the category if valid, or a BadRequest result if invalid.
    /// </summary>
    private (Category? Category, BadRequestObjectResult? Error) ValidateCategoryAndVisibility(
        int? categoryId, Visibility visibility, Dictionary<int, Category> categoryLookup, Collection collection)
    {
        Category? category = null;

        if (categoryId.HasValue)
        {
            if (!categoryLookup.TryGetValue(categoryId.Value, out category))
            {
                return (null, BadRequest("Invalid category"));
            }
        }

        if (visibility == Visibility.Public)
        {
            bool parentEffectivelyPublic = category?.EffectiveIsPublic ?? collection.EffectiveIsPublic;
            if (!parentEffectivelyPublic)
            {
                return (null, BadRequest("Cannot set visibility to Public when parent is private."));
            }
        }

        return (category, null);
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
            _visibilityService.ComputeEffectiveVisibility(categoryList, collection);
            var category = item.CategoryId.HasValue
                ? categoryList.FirstOrDefault(c => c.Id == item.CategoryId.Value)
                : null;
            _visibilityService.ComputeEffectiveVisibility(item, collection, category);
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
        var (_, categoryLookup) = await LoadCategoriesWithVisibility(request.CollectionId, workspaceId, collection);
        var (_, error) = ValidateCategoryAndVisibility(request.CategoryId, request.Visibility, categoryLookup, collection);
        if (error != null)
        {
            return error;
        }

        var item = request.ToItem(workspaceId);
        var created = await _itemRepository.CreateAsync(item);

        // Enqueue for matching if the item has a matchable flag
        if (created.UserFlag == UserFlag.Want || created.UserFlag == UserFlag.TradeOrSell)
        {
            await _matchingService.EnqueueForMatchingAsync(
                created.Id!.Value, workspaceId, MatchQueueReason.ItemCreated);
        }

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
        var (_, categoryLookup) = await LoadCategoriesWithVisibility(request.CollectionId, workspaceId, collection);
        var (_, error) = ValidateCategoryAndVisibility(request.CategoryId, request.Visibility, categoryLookup, collection);
        if (error != null)
        {
            return error;
        }

        // Capture old flag for matching logic
        var existingItem = await _itemRepository.GetByIdAsync(id, workspaceId);
        var oldFlag = existingItem?.UserFlag;

        var item = request.ToItem(id, workspaceId);
        var updated = await _itemRepository.UpdateAsync(id, item, workspaceId);
        if (updated is null)
        {
            return NotFound();
        }

        // Enqueue for matching on flag or content changes
        if (updated.UserFlag == UserFlag.Want || updated.UserFlag == UserFlag.TradeOrSell)
        {
            var reason = oldFlag != updated.UserFlag
                ? MatchQueueReason.UserFlagChanged
                : MatchQueueReason.ItemEdited;
            await _matchingService.EnqueueForMatchingAsync(id, workspaceId, reason);
        }
        else if (oldFlag == UserFlag.Want || oldFlag == UserFlag.TradeOrSell)
        {
            // Flag changed FROM Want/TradeOrSell to Have
            await _matchingService.EnqueueForMatchingAsync(id, workspaceId, MatchQueueReason.UserFlagChanged);
        }

        return Ok(updated);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteItem(int id)
    {
        var workspaceId = GetWorkspaceId();

        // Remove matches before deleting the item
        await _matchingService.RemoveMatchesForItemAsync(id);

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

