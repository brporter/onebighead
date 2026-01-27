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
    public async Task<ActionResult<IEnumerable<CategoryResponse>>> GetCategories([FromQuery] int? collectionId = null)
    {
        var tenantId = GetTenantId();
        
        List<Category> categoryList;
        Collection? collection;
        Dictionary<int, List<int>> templateIdsByCategory;
        
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
            templateIdsByCategory = await _categoryRepository.GetTemplateIdsByCategoryAsync(collectionId.Value, tenantId);
        }
        else
        {
            collection = await _collectionRepository.GetByTenantIdAsync(tenantId);
            var allCategories = await _categoryRepository.GetAllAsync(tenantId);
            categoryList = allCategories.ToList();
            templateIdsByCategory = collection != null 
                ? await _categoryRepository.GetTemplateIdsByCategoryAsync(collection.Id, tenantId)
                : new Dictionary<int, List<int>>();
        }
        
        // Compute effective visibility
        if (collection != null)
        {
            _visibilityService.ComputeEffectiveVisibility(categoryList, collection);
        }
        
        var response = categoryList.Select(c => CategoryResponse.FromCategory(
            c, 
            templateIdsByCategory.TryGetValue(c.Id, out var ids) ? ids : null
        ));
        
        return Ok(response);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<CategoryResponse>> GetCategory(int id)
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
        
        var templateIds = await _categoryRepository.GetTemplateIdsAsync(id, tenantId);
        return Ok(CategoryResponse.FromCategory(category, templateIds));
    }

    /// <summary>
    /// Gets item templates for a category, including inherited templates from parent categories.
    /// </summary>
    [HttpGet("{id}/templates")]
    public async Task<ActionResult<IEnumerable<int>>> GetCategoryTemplates(int id)
    {
        var tenantId = GetTenantId();
        var category = await _categoryRepository.GetByIdAsync(id, tenantId);
        if (category is null)
        {
            return NotFound();
        }
        
        var templateIds = await _categoryRepository.GetInheritedTemplateIdsAsync(id, tenantId);
        return Ok(templateIds);
    }

    [HttpPost]
    public async Task<ActionResult<CategoryResponse>> CreateCategory(CreateCategoryRequest request)
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
        
        // Set template associations if provided
        if (request.ItemTemplateIds != null && request.ItemTemplateIds.Count > 0)
        {
            await _categoryRepository.SetTemplateIdsAsync(created.Id, request.ItemTemplateIds, tenantId);
        }
        
        var templateIds = await _categoryRepository.GetTemplateIdsAsync(created.Id, tenantId);
        return CreatedAtAction(nameof(GetCategory), new { id = created.Id }, CategoryResponse.FromCategory(created, templateIds));
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<CategoryResponse>> UpdateCategory(int id, UpdateCategoryRequest request)
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
        
        // Update template associations if provided
        if (request.ItemTemplateIds != null)
        {
            await _categoryRepository.SetTemplateIdsAsync(id, request.ItemTemplateIds, tenantId);
        }
        
        var templateIds = await _categoryRepository.GetTemplateIdsAsync(id, tenantId);
        return Ok(CategoryResponse.FromCategory(updated, templateIds));
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
    public List<int>? ItemTemplateIds { get; set; }
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
    public List<int>? ItemTemplateIds { get; set; }
}

public class CategoryResponse
{
    public int CategoryId { get; set; }
    public int TenantId { get; set; }
    public int CollectionId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool IsSystem { get; set; }
    public int? ParentCategoryId { get; set; }
    public bool? IsPublicOverride { get; set; }
    public bool EffectiveIsPublic { get; set; }
    public List<int> ItemTemplateIds { get; set; } = new();

    public static CategoryResponse FromCategory(Category category, List<int>? templateIds = null)
    {
        return new CategoryResponse
        {
            CategoryId = category.Id,
            TenantId = category.TenantId,
            CollectionId = category.CollectionId,
            Name = category.Name,
            Description = category.Description,
            IsSystem = category.IsSystem,
            ParentCategoryId = category.ParentCategoryId,
            IsPublicOverride = category.IsPublicOverride,
            EffectiveIsPublic = category.EffectiveIsPublic,
            ItemTemplateIds = templateIds ?? new()
        };
    }
}

