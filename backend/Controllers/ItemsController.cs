using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
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

    public ItemsController(
        IItemRepository itemRepository, 
        ICategoryRepository categoryRepository,
        ICollectionRepository collectionRepository,
        IVisibilityService visibilityService)
    {
        _itemRepository = itemRepository;
        _categoryRepository = categoryRepository;
        _collectionRepository = collectionRepository;
        _visibilityService = visibilityService;
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<Item>>> GetItems(
        [FromQuery] int? categoryId = null,
        [FromQuery] bool includeDescendants = false,
        [FromQuery][Range(0, int.MaxValue)] int? skip = null,
        [FromQuery][Range(0, int.MaxValue)] int? take = null)
    {
        var tenantId = GetTenantId();

        IEnumerable<Item> items;
        if (categoryId == null)
        {
            items = await _itemRepository.GetAllAsync(tenantId);
        }
        else
        {
            IEnumerable<int> categoryIds;
            if (includeDescendants)
            {
                categoryIds = await GetCategoryAndDescendantIds(categoryId.Value, tenantId);
            }
            else
            {
                categoryIds = new[] { categoryId.Value };
            }
            items = await _itemRepository.GetByCategoryIdsAsync(categoryIds, tenantId);
        }

        var itemList = items.ToList();
        
        // Compute effective visibility
        var collection = await _collectionRepository.GetByTenantIdAsync(tenantId);
        if (collection != null)
        {
            var allCategories = await _categoryRepository.GetAllAsync(tenantId);
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

    private async Task<IEnumerable<int>> GetCategoryAndDescendantIds(int categoryId, int tenantId)
    {
        var allCategories = await _categoryRepository.GetAllAsync(tenantId);
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

    [HttpGet("{id}")]
    public async Task<ActionResult<Item>> GetItem(int id)
    {
        var tenantId = GetTenantId();
        var item = await _itemRepository.GetByIdAsync(id, tenantId);
        if (item is null)
        {
            return NotFound();
        }
        
        // Compute effective visibility
        var collection = await _collectionRepository.GetByTenantIdAsync(tenantId);
        if (collection != null)
        {
            var allCategories = await _categoryRepository.GetAllAsync(tenantId);
            var categoryList = allCategories.ToList();
            _visibilityService.ComputeEffectiveVisibility(categoryList, collection);
            var category = item.CategoryId.HasValue 
                ? categoryList.FirstOrDefault(c => c.Id == item.CategoryId.Value) 
                : null;
            _visibilityService.ComputeEffectiveVisibility(item, collection, category, categoryList);
        }
        
        return Ok(item);
    }

    [HttpPost]
    public async Task<ActionResult<Item>> CreateItem(CreateItemRequest request)
    {
        var tenantId = GetTenantId();
        
        // Validate CollectionId belongs to tenant
        var collection = await _collectionRepository.GetByIdAsync(request.CollectionId, tenantId);
        if (collection is null)
        {
            return BadRequest("Invalid collection");
        }
        
        // Validate CategoryId belongs to tenant and collection
        if (request.CategoryId.HasValue)
        {
            var category = await _categoryRepository.GetByIdAsync(request.CategoryId.Value, tenantId);
            if (category is null || category.CollectionId != request.CollectionId)
            {
                return BadRequest("Invalid category");
            }
        }
        
        var item = request.ToItem(tenantId);
        var created = await _itemRepository.CreateAsync(item);
        return CreatedAtAction(nameof(GetItem), new { id = created.Id }, created);
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<Item>> UpdateItem(int id, UpdateItemRequest request)
    {
        var tenantId = GetTenantId();
        
        // Validate CollectionId belongs to tenant
        var collection = await _collectionRepository.GetByIdAsync(request.CollectionId, tenantId);
        if (collection is null)
        {
            return BadRequest("Invalid collection");
        }
        
        // Validate CategoryId belongs to tenant and collection
        if (request.CategoryId.HasValue)
        {
            var category = await _categoryRepository.GetByIdAsync(request.CategoryId.Value, tenantId);
            if (category is null || category.CollectionId != request.CollectionId)
            {
                return BadRequest("Invalid category");
            }
        }
        
        var item = request.ToItem(id, tenantId);
        var updated = await _itemRepository.UpdateAsync(id, item, tenantId);
        if (updated is null)
        {
            return NotFound();
        }
        return Ok(updated);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteItem(int id)
    {
        var tenantId = GetTenantId();
        var deleted = await _itemRepository.DeleteAsync(id, tenantId);
        if (!deleted)
        {
            return NotFound();
        }
        return NoContent();
    }
}

