using OneBigHead.Server.Services;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Utilities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class CollectionsController : ApiControllerBase
{
    private readonly ICollectionRepository _collectionRepository;
    private readonly IItemTemplateRepository _itemTemplateRepository;
    private readonly ICollectionSetupService _setupService;
    private readonly IThemeRepository _themeRepository;
    private readonly ICollectionStatisticsRepository _collectionStatisticsRepository;

    public CollectionsController(
        ICollectionRepository collectionRepository,
        IItemTemplateRepository itemTemplateRepository,
        ICollectionSetupService setupService,
        IThemeRepository themeRepository,
        ICollectionStatisticsRepository collectionStatisticsRepository)
    {
        _collectionRepository = collectionRepository;
        _itemTemplateRepository = itemTemplateRepository;
        _setupService = setupService;
        _themeRepository = themeRepository;
        _collectionStatisticsRepository = collectionStatisticsRepository;
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<Collection>>> GetCollections()
    {
        var workspaceId = GetWorkspaceId();
        var collections = await _collectionRepository.GetAllAsync(workspaceId);
        return Ok(collections);
    }

    [HttpGet("{id:int}")]
    public async Task<ActionResult<Collection>> GetCollection(int id)
    {
        var workspaceId = GetWorkspaceId();
        var collection = await _collectionRepository.GetByIdAsync(id, workspaceId);
        if (collection is null)
        {
            return NotFound();
        }
        return Ok(collection);
    }

    [HttpGet("by-slug/{slug}")]
    public async Task<ActionResult<Collection>> GetCollectionBySlug(string slug)
    {
        var workspaceId = GetWorkspaceId();
        var collection = await _collectionRepository.GetBySlugAsync(slug, workspaceId);
        if (collection is null)
        {
            return NotFound();
        }
        return Ok(collection);
    }

    [HttpPost]
    [Authorize(Policy = "WorkspaceAdmin")]
    public async Task<ActionResult<Collection>> CreateCollection(CreateCollectionRequest request)
    {
        var workspaceId = GetWorkspaceId();

        var created = await _setupService.CreateAsync(new Collection
        {
            WorkspaceId = workspaceId,
            Name = request.Name,
            Description = request.Description ?? string.Empty,
            HeroImageUrl = request.HeroImageUrl
        }, null);

        return CreatedAtAction(nameof(GetCollection), new { id = created.Id }, created);
    }

    /// <summary>
    /// Creates a new collection with a theme applied (templates and categories).
    /// Used by the setup wizard for new users and when creating new collections.
    /// </summary>
    [HttpPost("setup")]
    [Authorize(Policy = "WorkspaceAdmin")]
    public async Task<ActionResult<Collection>> SetupCollection(SetupCollectionRequest request)
    {
        var workspaceId = GetWorkspaceId();

        // Get the theme
        var theme = await _themeRepository.GetByIdAsync(request.ThemeId);
        if (theme is null)
        {
            return BadRequest("Invalid theme");
        }

        var created = await _setupService.CreateAsync(new Collection
        {
            WorkspaceId = workspaceId,
            Name = request.Name,
            Description = request.Description ?? string.Empty,
            HeroImageUrl = request.HeroImageUrl
        }, theme);

        return CreatedAtAction(nameof(GetCollection), new { id = created.Id }, created);
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<Collection>> UpdateCollection(int id, UpdateCollectionRequest request)
    {
        var workspaceId = GetWorkspaceId();

        var existing = await _collectionRepository.GetByIdAsync(id, workspaceId);
        if (existing is null)
        {
            return NotFound();
        }

        var slug = SlugHelper.GenerateSlug(request.Name);
        
        // Check if slug is taken by another collection
        var slugCollection = await _collectionRepository.GetBySlugAsync(slug, workspaceId);
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
            Visibility = existing.Visibility
        };

        var updated = await _collectionRepository.UpdateAsync(id, collection, workspaceId);
        return Ok(updated);
    }

    [HttpDelete("{id}")]
    [Authorize(Policy = "WorkspaceAdmin")]
    public async Task<IActionResult> DeleteCollection(int id)
    {
        var workspaceId = GetWorkspaceId();

        // Check if this is the last collection
        var count = await _collectionRepository.GetCountAsync(workspaceId);
        if (count <= 1)
        {
            return BadRequest("Cannot delete the last collection. Users must have at least one collection.");
        }

        var deleted = await _collectionRepository.DeleteAsync(id, workspaceId);
        if (!deleted)
        {
            return NotFound();
        }
        return NoContent();
    }

    [HttpGet("{id}/statistics")]
    public async Task<ActionResult<CollectionStatisticsResponse>> GetStatistics(int id)
    {
        var workspaceId = GetWorkspaceId();

        var collection = await _collectionRepository.GetByIdAsync(id, workspaceId);
        if (collection is null)
        {
            return NotFound();
        }

        var aggregates = await _collectionStatisticsRepository.GetAggregatesAsync(id);
        var topViewed = await _collectionStatisticsRepository.GetTopViewedItemsAsync(id);
        var recentItems = await _collectionStatisticsRepository.GetRecentlyAddedItemsAsync(id, workspaceId);

        var response = new CollectionStatisticsResponse
        {
            ItemCount = aggregates.GetValueOrDefault(CollectionStatisticType.ItemCount),
            ImageCount = aggregates.GetValueOrDefault(CollectionStatisticType.ImageCount),
            TotalImageSizeBytes = aggregates.GetValueOrDefault(CollectionStatisticType.TotalImageSizeBytes),
            TopViewedItems = topViewed
                .Where(h => h.Item != null)
                .Select(h => new CollectionItemHighlightResponse
                {
                    ItemId = h.ItemId,
                    ItemName = h.Item!.Name,
                    ViewCount = h.ViewCount,
                })
                .ToList(),
            RecentlyAddedItems = recentItems
                .Select(i => new RecentItemResponse
                {
                    ItemId = i.Id!.Value,
                    ItemName = i.Name,
                    CreatedAt = i.CreatedAt,
                })
                .ToList(),
        };

        return Ok(response);
    }

    /// <summary>
    /// Gets item templates associated with a collection.
    /// </summary>
    [HttpGet("{id}/templates")]
    public async Task<ActionResult<IEnumerable<ItemTemplateResponse>>> GetCollectionTemplates(int id)
    {
        var workspaceId = GetWorkspaceId();

        var collection = await _collectionRepository.GetByIdAsync(id, workspaceId);
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
        var workspaceId = GetWorkspaceId();

        var collection = await _collectionRepository.GetByIdAsync(id, workspaceId);
        if (collection is null)
        {
            return NotFound("Collection not found");
        }

        // Verify template is accessible
        var template = await _itemTemplateRepository.GetByIdAsync(templateId, workspaceId);
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
        var workspaceId = GetWorkspaceId();

        var collection = await _collectionRepository.GetByIdAsync(id, workspaceId);
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
}
