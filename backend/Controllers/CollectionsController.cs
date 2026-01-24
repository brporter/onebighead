using backend.Data;
using backend.DTOs;
using backend.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;

namespace backend.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public partial class CollectionsController : ControllerBase
{
    private readonly ICollectionRepository _collectionRepository;
    private readonly ICategoryRepository _categoryRepository;
    private readonly IItemTemplateRepository _itemTemplateRepository;

    public CollectionsController(
        ICollectionRepository collectionRepository, 
        ICategoryRepository categoryRepository,
        IItemTemplateRepository itemTemplateRepository)
    {
        _collectionRepository = collectionRepository;
        _categoryRepository = categoryRepository;
        _itemTemplateRepository = itemTemplateRepository;
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

    private int GetUserId()
    {
        var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out var userId))
        {
            throw new UnauthorizedAccessException("User ID not found in token");
        }
        return userId;
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<Collection>>> GetCollections()
    {
        var tenantId = GetTenantId();
        var collections = await _collectionRepository.GetAllAsync(tenantId);
        return Ok(collections);
    }

    [HttpGet("{id:int}")]
    public async Task<ActionResult<Collection>> GetCollection(int id)
    {
        var tenantId = GetTenantId();
        var collection = await _collectionRepository.GetByIdAsync(id, tenantId);
        if (collection is null)
        {
            return NotFound();
        }
        return Ok(collection);
    }

    [HttpGet("by-slug/{slug}")]
    public async Task<ActionResult<Collection>> GetCollectionBySlug(string slug)
    {
        var tenantId = GetTenantId();
        var collection = await _collectionRepository.GetBySlugAsync(slug, tenantId);
        if (collection is null)
        {
            return NotFound();
        }
        return Ok(collection);
    }

    [HttpPost]
    public async Task<ActionResult<Collection>> CreateCollection(CreateCollectionRequest request)
    {
        var tenantId = GetTenantId();

        var slug = GenerateSlug(request.Name);
        
        // Ensure slug is unique within tenant
        var existing = await _collectionRepository.GetBySlugAsync(slug, tenantId);
        if (existing is not null)
        {
            slug = $"{slug}-{DateTime.UtcNow.Ticks}";
        }

        var collection = new Collection
        {
            TenantId = tenantId,
            Name = request.Name,
            Description = request.Description ?? string.Empty,
            HeroImageUrl = request.HeroImageUrl,
            Slug = slug
        };

        var created = await _collectionRepository.CreateAsync(collection);

        // Create default "Unassigned Items" category for the new collection
        var unassignedCategory = new Category
        {
            TenantId = tenantId,
            CollectionId = created.Id,
            Name = "Unassigned Items",
            Description = "Items that have not been assigned to a category",
            IsSystem = true
        };
        await _categoryRepository.CreateAsync(unassignedCategory);

        return CreatedAtAction(nameof(GetCollection), new { id = created.Id }, created);
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<Collection>> UpdateCollection(int id, UpdateCollectionRequest request)
    {
        var tenantId = GetTenantId();

        var existing = await _collectionRepository.GetByIdAsync(id, tenantId);
        if (existing is null)
        {
            return NotFound();
        }

        var slug = GenerateSlug(request.Name);
        
        // Check if slug is taken by another collection
        var slugCollection = await _collectionRepository.GetBySlugAsync(slug, tenantId);
        if (slugCollection is not null && slugCollection.Id != id)
        {
            slug = $"{slug}-{DateTime.UtcNow.Ticks}";
        }

        var collection = new Collection
        {
            Name = request.Name,
            Description = request.Description ?? string.Empty,
            HeroImageUrl = request.HeroImageUrl,
            Slug = slug
        };

        var updated = await _collectionRepository.UpdateAsync(id, collection, tenantId);
        return Ok(updated);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteCollection(int id)
    {
        var tenantId = GetTenantId();

        // Check if this is the last collection
        var count = await _collectionRepository.GetCountAsync(tenantId);
        if (count <= 1)
        {
            return BadRequest("Cannot delete the last collection. Users must have at least one collection.");
        }

        var deleted = await _collectionRepository.DeleteAsync(id, tenantId);
        if (!deleted)
        {
            return NotFound();
        }
        return NoContent();
    }

    /// <summary>
    /// Gets item templates associated with a collection.
    /// </summary>
    [HttpGet("{id}/templates")]
    public async Task<ActionResult<IEnumerable<ItemTemplateResponse>>> GetCollectionTemplates(int id)
    {
        var tenantId = GetTenantId();

        var collection = await _collectionRepository.GetByIdAsync(id, tenantId);
        if (collection is null)
        {
            return NotFound();
        }

        var templates = await _itemTemplateRepository.GetByCollectionAsync(id);
        var response = templates.Select(t => ItemTemplateResponse.FromItemTemplate(t, tenantId));
        return Ok(response);
    }

    /// <summary>
    /// Associates an item template with a collection.
    /// </summary>
    [HttpPost("{id}/templates/{templateId}")]
    public async Task<IActionResult> AssociateTemplate(int id, int templateId)
    {
        var tenantId = GetTenantId();

        var collection = await _collectionRepository.GetByIdAsync(id, tenantId);
        if (collection is null)
        {
            return NotFound("Collection not found");
        }

        // Verify template is accessible
        var template = await _itemTemplateRepository.GetByIdAsync(templateId, tenantId);
        if (template is null)
        {
            return NotFound("Template not found");
        }

        await _itemTemplateRepository.AssociateWithCollectionAsync(templateId, id);
        return NoContent();
    }

    /// <summary>
    /// Removes an item template association from a collection.
    /// </summary>
    [HttpDelete("{id}/templates/{templateId}")]
    public async Task<IActionResult> DisassociateTemplate(int id, int templateId)
    {
        var tenantId = GetTenantId();

        var collection = await _collectionRepository.GetByIdAsync(id, tenantId);
        if (collection is null)
        {
            return NotFound("Collection not found");
        }

        var removed = await _itemTemplateRepository.DisassociateFromCollectionAsync(templateId, id);
        if (!removed)
        {
            return NotFound("Template association not found");
        }

        return NoContent();
    }

    private static string GenerateSlug(string name)
    {
        var slug = name.ToLowerInvariant();
        slug = SlugInvalidCharsRegex().Replace(slug, "");
        slug = SlugWhitespaceRegex().Replace(slug, "-");
        slug = SlugMultipleDashRegex().Replace(slug, "-");
        slug = slug.Trim('-');
        return string.IsNullOrEmpty(slug) ? "collection" : slug;
    }

    [GeneratedRegex("[^a-z0-9\\s-]")]
    private static partial Regex SlugInvalidCharsRegex();

    [GeneratedRegex("\\s+")]
    private static partial Regex SlugWhitespaceRegex();

    [GeneratedRegex("-+")]
    private static partial Regex SlugMultipleDashRegex();
}

public class CreateCollectionRequest
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string? HeroImageUrl { get; set; }
}

public class UpdateCollectionRequest
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string? HeroImageUrl { get; set; }
}
