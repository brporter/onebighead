using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class CategoriesController : ApiControllerBase
{
    private readonly ICategoryRepository _categoryRepository;
    private readonly ICollectionRepository _collectionRepository;
    private readonly IPublishManagerService _publishManagerService;

    public CategoriesController(
        ICategoryRepository categoryRepository, 
        ICollectionRepository collectionRepository,
        IPublishManagerService publishManagerService)
    {
        _categoryRepository = categoryRepository;
        _collectionRepository = collectionRepository;
        _publishManagerService = publishManagerService;
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<CategoryResponse>>> GetCategories([FromQuery] int? collectionId = null)
    {
        var workspaceId = GetWorkspaceId();
        
        List<Category> categoryList;
        Collection? collection;
        Dictionary<int, List<int>> templateIdsByCategory;
        
        if (collectionId.HasValue)
        {
            // Verify collection belongs to workspace
            collection = await _collectionRepository.GetByIdAsync(collectionId.Value, workspaceId);
            if (collection is null)
            {
                return NotFound("Collection not found");
            }
            var categories = await _categoryRepository.GetByCollectionAsync(collectionId.Value, workspaceId);
            categoryList = categories.ToList();
            templateIdsByCategory = await _categoryRepository.GetTemplateIdsByCategoryAsync(collectionId.Value, workspaceId);
        }
        else
        {
            collection = await _collectionRepository.GetByWorkspaceIdAsync(workspaceId);
            var allCategories = await _categoryRepository.GetAllAsync(workspaceId);
            categoryList = allCategories.ToList();
            templateIdsByCategory = collection != null 
                ? await _categoryRepository.GetTemplateIdsByCategoryAsync(collection.Id, workspaceId)
                : new Dictionary<int, List<int>>();
        }
        
        // Compute effective visibility
        if (collection != null)
        {
            _publishManagerService.ComputeEffectiveVisibility(categoryList, collection);
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
        var workspaceId = GetWorkspaceId();
        var category = await _categoryRepository.GetByIdAsync(id, workspaceId);
        if (category is null)
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
            
            // Find the category in the computed list to get the effective visibility
            var computed = categoryList.FirstOrDefault(c => c.Id == id);
            if (computed != null)
            {
                category.EffectiveIsPublic = computed.EffectiveIsPublic;
            }
        }
        
        var templateIds = await _categoryRepository.GetTemplateIdsAsync(id, workspaceId);
        return Ok(CategoryResponse.FromCategory(category, templateIds));
    }

    /// <summary>
    /// Gets item templates for a category, including inherited templates from parent categories.
    /// </summary>
    [HttpGet("{id}/templates")]
    public async Task<ActionResult<IEnumerable<int>>> GetCategoryTemplates(int id)
    {
        var workspaceId = GetWorkspaceId();
        var category = await _categoryRepository.GetByIdAsync(id, workspaceId);
        if (category is null)
        {
            return NotFound();
        }
        
        var templateIds = await _categoryRepository.GetInheritedTemplateIdsAsync(id, workspaceId);
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

        var workspaceId = GetWorkspaceId();

        // Verify collection belongs to workspace
        var collection = await _collectionRepository.GetByIdAsync(request.CollectionId, workspaceId);
        if (collection is null)
        {
            return BadRequest("Invalid collection");
        }

        // Get all categories for visibility computation
        var allCategories = (await _categoryRepository.GetByCollectionAsync(request.CollectionId, workspaceId)).ToList();
        _publishManagerService.ComputeEffectiveVisibility(allCategories, collection);
        var categoryLookup = allCategories.ToDictionary(c => c.Id);

        // Validate ParentCategoryId belongs to workspace and same collection
        Category? parentCategory = null;
        if (request.ParentCategoryId.HasValue)
        {
            if (!categoryLookup.TryGetValue(request.ParentCategoryId.Value, out parentCategory))
            {
                return BadRequest("Invalid parent category");
            }
        }

        // Default visibility from parent category or collection
        var defaultVisibility = parentCategory?.EffectiveIsPublic ?? collection.EffectiveIsPublic
            ? Visibility.Public
            : Visibility.Private;

        var category = new Category
        {
            WorkspaceId = workspaceId,
            CollectionId = request.CollectionId,
            Name = request.Name,
            Description = request.Description ?? string.Empty,
            ParentCategoryId = request.ParentCategoryId,
            IsSystem = false,
            Visibility = defaultVisibility
        };

        var created = await _categoryRepository.CreateAsync(category);
        
        // Set template associations if provided
        if (request.ItemTemplateIds != null && request.ItemTemplateIds.Count > 0)
        {
            await _categoryRepository.SetTemplateIdsAsync(created.Id, request.ItemTemplateIds, workspaceId);
        }
        
        var templateIds = await _categoryRepository.GetTemplateIdsAsync(created.Id, workspaceId);
        return CreatedAtAction(nameof(GetCategory), new { id = created.Id }, CategoryResponse.FromCategory(created, templateIds));
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<CategoryResponse>> UpdateCategory(int id, UpdateCategoryRequest request)
    {
        var workspaceId = GetWorkspaceId();
        
        // Check if attempting to modify a system category
        var existingCategory = await _categoryRepository.GetByIdAsync(id, workspaceId);
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

        // Get collection for visibility checks
        var collection = await _collectionRepository.GetByIdAsync(existingCategory.CollectionId, workspaceId);
        if (collection is null)
        {
            return NotFound("Collection not found");
        }

        // Get all categories for visibility computation
        var allCategories = (await _categoryRepository.GetByCollectionAsync(existingCategory.CollectionId, workspaceId)).ToList();
        _publishManagerService.ComputeEffectiveVisibility(allCategories, collection);
        var categoryLookup = allCategories.ToDictionary(c => c.Id);

        // Validate ParentCategoryId belongs to workspace and same collection
        if (request.ParentCategoryId.HasValue)
        {
            if (!categoryLookup.TryGetValue(request.ParentCategoryId.Value, out _))
            {
                return BadRequest("Invalid parent category");
            }
        }

        var category = new Category
        {
            WorkspaceId = workspaceId,
            CollectionId = existingCategory.CollectionId,
            Name = request.Name,
            Description = request.Description ?? string.Empty,
            ParentCategoryId = request.ParentCategoryId,
            Visibility = existingCategory.Visibility
        };

        var updated = await _categoryRepository.UpdateAsync(id, category, workspaceId);
        if (updated is null)
        {
            return NotFound();
        }
        
        // Update template associations if provided
        if (request.ItemTemplateIds != null)
        {
            await _categoryRepository.SetTemplateIdsAsync(id, request.ItemTemplateIds, workspaceId);
        }
        
        var templateIds = await _categoryRepository.GetTemplateIdsAsync(id, workspaceId);
        return Ok(CategoryResponse.FromCategory(updated, templateIds));
    }

    [HttpPut("reorder")]
    public async Task<ActionResult<IEnumerable<CategoryResponse>>> ReorderCategories(ReorderCategoriesRequest request)
    {
        var workspaceId = GetWorkspaceId();

        if (request.Categories.Count == 0)
        {
            return BadRequest("No categories to reorder");
        }

        // Reject duplicate category IDs
        var categoryIds = request.Categories.Select(c => c.CategoryId).ToList();
        if (categoryIds.Count != categoryIds.Distinct().Count())
        {
            return BadRequest("Duplicate category IDs are not allowed");
        }

        // Validate all categories belong to this workspace
        var existingCategories = new List<Category>();
        foreach (var id in categoryIds)
        {
            var cat = await _categoryRepository.GetByIdAsync(id, workspaceId);
            if (cat is null)
            {
                return BadRequest($"Category {id} not found in workspace");
            }
            existingCategories.Add(cat);
        }

        // Validate all categories belong to the same collection
        var collectionIds = existingCategories.Select(c => c.CollectionId).Distinct().ToList();
        if (collectionIds.Count > 1)
        {
            return BadRequest("All categories must belong to the same collection");
        }

        var updates = request.Categories.ToDictionary(c => c.CategoryId, c => c.SortOrder);
        await _categoryRepository.ReorderAsync(updates, workspaceId);

        // Return updated category list
        var collectionId = collectionIds[0];
        var collection = await _collectionRepository.GetByIdAsync(collectionId, workspaceId);
        var allCategories = (await _categoryRepository.GetByCollectionAsync(collectionId, workspaceId)).ToList();
        if (collection != null)
        {
            _publishManagerService.ComputeEffectiveVisibility(allCategories, collection);
        }
        var templateIdsByCategory = await _categoryRepository.GetTemplateIdsByCategoryAsync(collectionId, workspaceId);
        var response = allCategories.Select(c => CategoryResponse.FromCategory(
            c,
            templateIdsByCategory.TryGetValue(c.Id, out var ids) ? ids : null
        ));
        return Ok(response);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteCategory(int id)
    {
        var workspaceId = GetWorkspaceId();
        
        // Check if attempting to delete a system category
        var existingCategory = await _categoryRepository.GetByIdAsync(id, workspaceId);
        if (existingCategory is null)
        {
            return NotFound();
        }
        if (existingCategory.IsSystem)
        {
            return StatusCode(403, "System categories cannot be deleted.");
        }

        var deleted = await _categoryRepository.DeleteAsync(id, workspaceId);
        if (!deleted)
        {
            return NotFound();
        }
        return NoContent();
    }
}

