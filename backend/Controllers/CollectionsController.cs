using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public partial class CollectionsController : ApiControllerBase
{
    private readonly ICollectionRepository _collectionRepository;
    private readonly ICategoryRepository _categoryRepository;
    private readonly IItemTemplateRepository _itemTemplateRepository;
    private readonly IThemeRepository _themeRepository;
    private readonly ILogger<CollectionsController> _logger;

    public CollectionsController(
        ICollectionRepository collectionRepository, 
        ICategoryRepository categoryRepository,
        IItemTemplateRepository itemTemplateRepository,
        IThemeRepository themeRepository,
        ILogger<CollectionsController> logger)
    {
        _collectionRepository = collectionRepository;
        _categoryRepository = categoryRepository;
        _itemTemplateRepository = itemTemplateRepository;
        _themeRepository = themeRepository;
        _logger = logger;
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
            Visibility = request.Visibility
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
            Visibility = request.Visibility
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

        // Apply theme templates to collection in batch
        var templateIds = theme.ThemeTemplates
            .Where(t => t.ItemTemplateId > 0)
            .OrderBy(t => t.SortOrder)
            .Select(t => t.ItemTemplateId)
            .ToList();
        
        if (templateIds.Count > 0)
        {
            await _itemTemplateRepository.AssociateMultipleWithCollectionAsync(templateIds, created.Id);
        }

        // Create categories from theme in batch
        // Use iterative approach to handle arbitrary nesting depth
        var categoryMap = new Dictionary<string, int>(); // name -> categoryId
        var remainingCategories = theme.ThemeCategories.OrderBy(c => c.SortOrder).ToList();
        var maxIterations = remainingCategories.Count + 1; // Prevent infinite loops
        var iteration = 0;
        
        while (remainingCategories.Count > 0 && iteration < maxIterations)
        {
            iteration++;
            var categoriesToCreate = new List<(CollectionThemeCategory theme, Category entity)>();
            var stillRemaining = new List<CollectionThemeCategory>();
            
            foreach (var tc in remainingCategories)
            {
                int? parentId = null;
                
                if (tc.ParentName == null)
                {
                    // Root category - can create immediately
                }
                else if (categoryMap.TryGetValue(tc.ParentName, out var id))
                {
                    // Parent exists - can create
                    parentId = id;
                }
                else
                {
                    // Parent not yet created - defer to next iteration
                    stillRemaining.Add(tc);
                    continue;
                }
                
                categoriesToCreate.Add((tc, new Category
                {
                    TenantId = tenantId,
                    CollectionId = created.Id,
                    Name = tc.Name,
                    Description = tc.Description,
                    ParentCategoryId = parentId,
                    IsSystem = false
                }));
            }
            
            if (categoriesToCreate.Count > 0)
            {
                var createdCategories = await _categoryRepository.CreateManyAsync(
                    categoriesToCreate.Select(c => c.entity));
                
                // Add created categories to map for next iteration
                foreach (var cat in createdCategories)
                {
                    categoryMap[cat.Name] = cat.Id;
                }
            }
            
            remainingCategories = stillRemaining;
        }
        
        // Log warning for any categories that couldn't be created (circular references or missing parents)
        foreach (var orphan in remainingCategories)
        {
            _logger.LogWarning("Theme category '{CategoryName}' could not be created - parent '{ParentName}' not found or circular reference detected", 
                orphan.Name, orphan.ParentName);
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
            Visibility = request.Visibility
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
