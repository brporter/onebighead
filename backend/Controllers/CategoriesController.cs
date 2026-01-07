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

    public CategoriesController(ICategoryRepository categoryRepository)
    {
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
    public async Task<ActionResult<IEnumerable<Category>>> GetCategories()
    {
        var tenantId = GetTenantId();
        var categories = await _categoryRepository.GetAllAsync(tenantId);
        return Ok(categories);
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
    public async Task<ActionResult<Category>> CreateCategory(Category category)
    {
        // Prevent creation of categories with reserved system names
        if (string.Equals(category.Name, "Unassigned Items", StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest("The name 'Unassigned Items' is reserved for system use.");
        }

        var tenantId = GetTenantId();
        category.TenantId = tenantId;
        category.IsSystem = false; // User-created categories are never system categories
        var created = await _categoryRepository.CreateAsync(category);
        return CreatedAtAction(nameof(GetCategory), new { id = created.Id }, created);
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<Category>> UpdateCategory(int id, Category category)
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
        if (string.Equals(category.Name, "Unassigned Items", StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest("The name 'Unassigned Items' is reserved for system use.");
        }

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

