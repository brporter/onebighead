using backend.Data;
using backend.DTOs;
using backend.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace backend.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public partial class CollectionsController : ApiControllerBase
{
    private readonly ICollectionRepository _collectionRepository;
    private readonly ICategoryRepository _categoryRepository;
    private readonly IItemTemplateRepository _itemTemplateRepository;
    private readonly IThemeRepository _themeRepository;

    public CollectionsController(
        ICollectionRepository collectionRepository, 
        ICategoryRepository categoryRepository,
        IItemTemplateRepository itemTemplateRepository,
        IThemeRepository themeRepository)
    {
        _collectionRepository = collectionRepository;
        _categoryRepository = categoryRepository;
        _itemTemplateRepository = itemTemplateRepository;
        _themeRepository = themeRepository;
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
            Slug = slug,
            IsPublic = request.IsPublic
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

    /// <summary>
    /// Creates a new collection with a theme applied (templates and categories).
    /// Used by the setup wizard for new users and when creating new collections.
    /// </summary>
    [HttpPost("setup")]
    public async Task<ActionResult<Collection>> SetupCollection(SetupCollectionRequest request)
    {
        var tenantId = GetTenantId();

        // Get the theme
        var theme = await _themeRepository.GetByIdAsync(request.ThemeId);
        if (theme is null)
        {
            return BadRequest("Invalid theme");
        }

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
            Slug = slug,
            IsPublic = request.IsPublic
        };

        var created = await _collectionRepository.CreateAsync(collection);

        // Create "Unassigned Items" system category
        var unassignedCategory = new Category
        {
            TenantId = tenantId,
            CollectionId = created.Id,
            Name = "Unassigned Items",
            Description = "Items that have not been assigned to a category",
            IsSystem = true
        };
        await _categoryRepository.CreateAsync(unassignedCategory);

        // Apply theme templates to collection
        foreach (var themeTemplate in theme.ThemeTemplates.OrderBy(t => t.SortOrder))
        {
            if (themeTemplate.ItemTemplateId > 0)
            {
                await _itemTemplateRepository.AssociateWithCollectionAsync(themeTemplate.ItemTemplateId, created.Id);
            }
        }

        // Create categories from theme
        // First pass: create root categories (no parent)
        var categoryMap = new Dictionary<string, int>(); // name -> categoryId
        foreach (var themeCategory in theme.ThemeCategories.Where(c => c.ParentName == null).OrderBy(c => c.SortOrder))
        {
            var category = new Category
            {
                TenantId = tenantId,
                CollectionId = created.Id,
                Name = themeCategory.Name,
                Description = themeCategory.Description,
                ParentCategoryId = null,
                IsSystem = false
            };
            var createdCategory = await _categoryRepository.CreateAsync(category);
            categoryMap[themeCategory.Name] = createdCategory.Id;
        }

        // Second pass: create child categories
        foreach (var themeCategory in theme.ThemeCategories.Where(c => c.ParentName != null).OrderBy(c => c.SortOrder))
        {
            var parentId = categoryMap.TryGetValue(themeCategory.ParentName!, out var id) ? id : (int?)null;
            var category = new Category
            {
                TenantId = tenantId,
                CollectionId = created.Id,
                Name = themeCategory.Name,
                Description = themeCategory.Description,
                ParentCategoryId = parentId,
                IsSystem = false
            };
            var createdCategory = await _categoryRepository.CreateAsync(category);
            categoryMap[themeCategory.Name] = createdCategory.Id;
        }

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
            Slug = slug,
            IsPublic = request.IsPublic
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
        var response = templates.Select(ItemTemplateResponse.FromItemTemplate);
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
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string? Description { get; set; }

    [MaxLength(500)]
    public string? HeroImageUrl { get; set; }
    public bool IsPublic { get; set; } = false;
}

public class UpdateCollectionRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string? Description { get; set; }

    [MaxLength(500)]
    public string? HeroImageUrl { get; set; }
    public bool IsPublic { get; set; } = false;
}

public class SetupCollectionRequest
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string? Description { get; set; }

    [MaxLength(500)]
    public string? HeroImageUrl { get; set; }
    
    public bool IsPublic { get; set; } = false;

    /// <summary>
    /// The theme ID to apply to the new collection.
    /// </summary>
    [Required]
    public int ThemeId { get; set; }
}
