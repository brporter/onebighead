using backend.Data;
using backend.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace backend.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ItemsController : ControllerBase
{
    private readonly IItemRepository _itemRepository;
    private readonly ICategoryRepository _categoryRepository;

    public ItemsController(IItemRepository itemRepository, ICategoryRepository categoryRepository)
    {
        _itemRepository = itemRepository;
        _categoryRepository = categoryRepository;
    }

    private int GetTenantId()
    {
        var tenantIdClaim = User.FindFirst("tenant_id")?.Value;
        if (string.IsNullOrEmpty(tenantIdClaim) || !int.TryParse(tenantIdClaim, out var tenantId))
        {
            throw new UnauthorizedAccessException("Tenant ID not found in token");
        }
        return tenantId;
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<Item>>> GetItems(
        [FromQuery] int? categoryId = null,
        [FromQuery] bool includeDescendants = false)
    {
        var tenantId = GetTenantId();

        if (categoryId == null)
        {
            var allItems = await _itemRepository.GetAllAsync(tenantId);
            return Ok(allItems);
        }

        IEnumerable<int> categoryIds;
        if (includeDescendants)
        {
            categoryIds = await GetCategoryAndDescendantIds(categoryId.Value, tenantId);
        }
        else
        {
            categoryIds = new[] { categoryId.Value };
        }

        var items = await _itemRepository.GetByCategoryIdsAsync(categoryIds, tenantId);
        return Ok(items);
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
        return Ok(item);
    }

    [HttpPost]
    public async Task<ActionResult<Item>> CreateItem(Item item)
    {
        var tenantId = GetTenantId();
        item.TenantId = tenantId;
        var created = await _itemRepository.CreateAsync(item);
        return CreatedAtAction(nameof(GetItem), new { id = created.Id }, created);
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<Item>> UpdateItem(int id, Item item)
    {
        var tenantId = GetTenantId();
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

