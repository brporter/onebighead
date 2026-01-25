using backend.Data;
using backend.Models;
using backend.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace backend.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class CategoriesController : ApiControllerBase
{
    private readonly ICategoryRepository _categoryRepository;
    private readonly ICollectionRepository _collectionRepository;
    private readonly IVisibilityService _visibilityService;

    public CategoriesController(
        ICategoryRepository categoryRepository, 
        ICollectionRepository collectionRepository,
        IVisibilityService visibilityService)
    {
        _categoryRepository = categoryRepository;
        _collectionRepository = collectionRepository;
        _visibilityService = visibilityService;
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<Category>>> GetCategories([FromQuery] int? collectionId = null)
    {
        var tenantId = GetTenantId();
        
        List<Category> categoryList;
        Collection? collection;
        
        if (collectionId.HasValue)
        {
            // Verify collection belongs to tenant
            collection = await _collectionRepository.GetByIdAsync(collectionId.Value, tenantId);
            if (collection is null)
            {
                return NotFound("Collection not found");
            }
            var categories = await _categoryRepository.GetByCollectionAsync(collectionId.Value, tenantId);
            categoryList = categories.ToList();
        }
        else
        {
            collection = await _collectionRepository.GetByTenantIdAsync(tenantId);
            var allCategories = await _categoryRepository.GetAllAsync(tenantId);
            categoryList = allCategories.ToList();
        }
        
        // Compute effective visibility
        if (collection != null)
        {
            _visibilityService.ComputeEffectiveVisibility(categoryList, collection);
        }
        
        return Ok(categoryList);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<Category>> GetCategory(int id)
    {
        var tenantId = GetTenantId();
        var category = await _categoryRepository.GetByIdAsync(id, tenantId);
        if (category is null)
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
            
            // Find the category in the computed list to get the effective visibility
            var computed = categoryList.FirstOrDefault(c => c.Id == id);
            if (computed != null)
            {
                category.EffectiveIsPublic = computed.EffectiveIsPublic;
            }
        }
        
        return Ok(category);
    }

    [HttpPost]
    public async Task<ActionResult<Category>> CreateCategory(CreateCategoryRequest request)
    {
        // Prevent creation of categories with reserved system names
        if (string.Equals(request.Name, "Unassigned Items", StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest("The name 'Unassigned Items' is reserved for system use.");
        }

        var tenantId = GetTenantId();

        // Verify collection belongs to tenant
        var collection = await _collectionRepository.GetByIdAsync(request.CollectionId, tenantId);
        if (collection is null)
        {
            return BadRequest("Invalid collection");
        }

        // Validate ParentCategoryId belongs to tenant and same collection
        if (request.ParentCategoryId.HasValue)
        {
            var parentCategory = await _categoryRepository.GetByIdAsync(request.ParentCategoryId.Value, tenantId);
            if (parentCategory is null || parentCategory.CollectionId != request.CollectionId)
            {
                return BadRequest("Invalid parent category");
            }
        }

        var category = new Category
        {
            TenantId = tenantId,
            CollectionId = request.CollectionId,
            Name = request.Name,
            Description = request.Description ?? string.Empty,
            ParentCategoryId = request.ParentCategoryId,
            IsSystem = false,
            IsPublicOverride = request.IsPublicOverride
        };

        var created = await _categoryRepository.CreateAsync(category);
        return CreatedAtAction(nameof(GetCategory), new { id = created.Id }, created);
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<Category>> UpdateCategory(int id, UpdateCategoryRequest request)
    {
        var tenantId = GetTenantId();
        
        // Check if attempting to modify a system category
        var existingCategory = await _categoryRepository.GetByIdAsync(id, tenantId);
        if (existingCategory is null)
        {
            return NotFound();
        }
        if (existingCategory.IsSystem)
        {
            return StatusCode(403, "System categories cannot be modified.");
        }

        // Prevent renaming to reserved system names
        if (string.Equals(request.Name, "Unassigned Items", StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest("The name 'Unassigned Items' is reserved for system use.");
        }

        // Validate ParentCategoryId belongs to tenant and same collection
        if (request.ParentCategoryId.HasValue)
        {
            var parentCategory = await _categoryRepository.GetByIdAsync(request.ParentCategoryId.Value, tenantId);
            if (parentCategory is null || parentCategory.CollectionId != existingCategory.CollectionId)
            {
                return BadRequest("Invalid parent category");
            }
        }

        var category = new Category
        {
            TenantId = tenantId,
            CollectionId = existingCategory.CollectionId,
            Name = request.Name,
            Description = request.Description ?? string.Empty,
            ParentCategoryId = request.ParentCategoryId,
            IsPublicOverride = request.IsPublicOverride
        };

        var updated = await _categoryRepository.UpdateAsync(id, category, tenantId);
        if (updated is null)
        {
            return NotFound();
        }
        return Ok(updated);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteCategory(int id)
    {
        var tenantId = GetTenantId();
        
        // Check if attempting to delete a system category
        var existingCategory = await _categoryRepository.GetByIdAsync(id, tenantId);
        if (existingCategory is null)
        {
            return NotFound();
        }
        if (existingCategory.IsSystem)
        {
            return StatusCode(403, "System categories cannot be deleted.");
        }

        var deleted = await _categoryRepository.DeleteAsync(id, tenantId);
        if (!deleted)
        {
            return NotFound();
        }
        return NoContent();
    }
}

public class CreateCategoryRequest
{
    public int CollectionId { get; set; }

    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string? Description { get; set; }
    public int? ParentCategoryId { get; set; }
    public bool? IsPublicOverride { get; set; }
}

public class UpdateCategoryRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string? Description { get; set; }
    public int? ParentCategoryId { get; set; }
    public bool? IsPublicOverride { get; set; }
}

