﻿using backend.Data;
using backend.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace backend.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class CategoriesController : ControllerBase
{
    private readonly ICategoryRepository _categoryRepository;
    private readonly ICollectionRepository _collectionRepository;

    public CategoriesController(ICategoryRepository categoryRepository, ICollectionRepository collectionRepository)
    {
        _categoryRepository = categoryRepository;
        _collectionRepository = collectionRepository;
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
    public async Task<ActionResult<IEnumerable<Category>>> GetCategories([FromQuery] int? collectionId = null)
    {
        var tenantId = GetTenantId();
        
        if (collectionId.HasValue)
        {
            // Verify collection belongs to tenant
            var collection = await _collectionRepository.GetByIdAsync(collectionId.Value, tenantId);
            if (collection is null)
            {
                return NotFound("Collection not found");
            }
            var categories = await _categoryRepository.GetByCollectionAsync(collectionId.Value, tenantId);
            return Ok(categories);
        }
        
        var allCategories = await _categoryRepository.GetAllAsync(tenantId);
        return Ok(allCategories);
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

        var category = new Category
        {
            TenantId = tenantId,
            CollectionId = request.CollectionId,
            Name = request.Name,
            Description = request.Description ?? string.Empty,
            ParentCategoryId = request.ParentCategoryId,
            IsSystem = false
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

        var category = new Category
        {
            TenantId = tenantId,
            CollectionId = existingCategory.CollectionId,
            Name = request.Name,
            Description = request.Description ?? string.Empty,
            ParentCategoryId = request.ParentCategoryId
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
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public int? ParentCategoryId { get; set; }
}

public class UpdateCategoryRequest
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public int? ParentCategoryId { get; set; }
}

