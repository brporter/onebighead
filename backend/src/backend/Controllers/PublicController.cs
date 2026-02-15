using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;

namespace OneBigHead.Server.Controllers;

// TODO: Add rate limiting to public endpoints using the existing rate limiting infrastructure in Program.cs
[ApiController]
[Route("api/public")]
[AllowAnonymous]
public class PublicController : ControllerBase
{
    private readonly IWorkspaceRepository _workspaceRepository;
    private readonly ICollectionRepository _collectionRepository;
    private readonly ICategoryRepository _categoryRepository;
    private readonly IItemRepository _itemRepository;
    private readonly IVisibilityService _visibilityService;

    public PublicController(
        IWorkspaceRepository workspaceRepository,
        ICollectionRepository collectionRepository,
        ICategoryRepository categoryRepository,
        IItemRepository itemRepository,
        IVisibilityService visibilityService)
    {
        _workspaceRepository = workspaceRepository;
        _collectionRepository = collectionRepository;
        _categoryRepository = categoryRepository;
        _itemRepository = itemRepository;
        _visibilityService = visibilityService;
    }

    /// <summary>
    /// Get a workspace by its public slug.
    /// </summary>
    [HttpGet("{slug}")]
    public async Task<ActionResult<PublicWorkspaceDto>> GetWorkspace(string slug)
    {
        var workspace = await _workspaceRepository.GetBySlugAsync(slug);
        if (workspace == null)
            return NotFound();

        return Ok(new PublicWorkspaceDto
        {
            Name = workspace.Name,
            Slug = workspace.Slug ?? string.Empty
        });
    }

    /// <summary>
    /// List all public collections in a workspace.
    /// </summary>
    // TODO: Add pagination when collection sizes warrant it. Note: EffectiveIsPublic is computed
    // in-memory, so DB-level pagination requires denormalizing visibility into a persisted column.
    [HttpGet("{slug}/collections")]
    public async Task<ActionResult<List<PublicCollectionDto>>> GetCollections(string slug)
    {
        var workspace = await _workspaceRepository.GetBySlugAsync(slug);
        if (workspace == null)
            return NotFound();

        var collections = await _collectionRepository.GetAllAsync(workspace.Id);
        var publicCollections = collections
            .Where(c => c.EffectiveIsPublic)
            .Select(c => new PublicCollectionDto
            {
                Id = c.Id,
                Name = c.Name,
                Description = c.Description,
                HeroImageUrl = ToPublicImageUrl(c.HeroImageUrl),
                Slug = c.Slug
            })
            .ToList();

        return Ok(publicCollections);
    }

    /// <summary>
    /// Get collection detail with public categories.
    /// </summary>
    [HttpGet("{slug}/collections/{collectionId:int}")]
    public async Task<ActionResult<PublicCollectionDetailDto>> GetCollectionDetail(string slug, int collectionId)
    {
        var workspace = await _workspaceRepository.GetBySlugAsync(slug);
        if (workspace == null)
            return NotFound();

        var collection = await _collectionRepository.GetByIdAsync(collectionId, workspace.Id);
        if (collection == null || !collection.EffectiveIsPublic)
            return NotFound();

        var categories = (await _categoryRepository.GetByCollectionAsync(collectionId, workspace.Id)).ToList();
        _visibilityService.ComputeEffectiveVisibility(categories, collection);

        var templateIdsByCategory = await _categoryRepository.GetTemplateIdsByCategoryAsync(collectionId, workspace.Id);

        var publicCategories = categories
            .Where(c => c.EffectiveIsPublic)
            .Select(c => new PublicCategoryDto
            {
                Id = c.Id,
                Name = c.Name,
                ParentCategoryId = c.ParentCategoryId,
                IsSystem = c.IsSystem,
                ItemTemplateIds = templateIdsByCategory.TryGetValue(c.Id, out var ids) ? ids : new List<int>()
            })
            .ToList();

        return Ok(new PublicCollectionDetailDto
        {
            Collection = new PublicCollectionDto
            {
                Id = collection.Id,
                Name = collection.Name,
                Description = collection.Description,
                HeroImageUrl = ToPublicImageUrl(collection.HeroImageUrl),
                Slug = collection.Slug
            },
            Categories = publicCategories
        });
    }

    /// <summary>
    /// List public items in a collection, with optional category filter.
    /// </summary>
    // TODO: Add pagination when collection sizes warrant it. Note: EffectiveIsPublic is computed
    // in-memory, so DB-level pagination requires denormalizing visibility into a persisted column.
    [HttpGet("{slug}/collections/{collectionId:int}/items")]
    public async Task<ActionResult<List<PublicItemSummaryDto>>> GetItems(string slug, int collectionId, [FromQuery] int? categoryId)
    {
        var workspace = await _workspaceRepository.GetBySlugAsync(slug);
        if (workspace == null)
            return NotFound();

        var collection = await _collectionRepository.GetByIdAsync(collectionId, workspace.Id);
        if (collection == null || !collection.EffectiveIsPublic)
            return NotFound();

        var categories = (await _categoryRepository.GetByCollectionAsync(collectionId, workspace.Id)).ToList();
        _visibilityService.ComputeEffectiveVisibility(categories, collection);

        var items = (await _itemRepository.GetByCollectionIdAsync(collectionId, workspace.Id)).ToList();
        _visibilityService.ComputeEffectiveVisibility(items, collection, categories);

        var publicItems = items
            .Where(i => i.EffectiveIsPublic)
            .Where(i => categoryId == null || i.CategoryId == categoryId)
            .Select(i => new PublicItemSummaryDto
            {
                Id = i.Id ?? 0,
                Name = i.Name,
                Summary = i.Summary,
                PrimaryImageUrl = ToPublicImageUrl(i.Images.FirstOrDefault()?.Url),
                CategoryId = i.CategoryId
            })
            .ToList();

        return Ok(publicItems);
    }

    /// <summary>
    /// Get public item detail with properties and images.
    /// </summary>
    [HttpGet("{slug}/items/{itemId:int}")]
    public async Task<ActionResult<PublicItemDto>> GetItem(string slug, int itemId)
    {
        var workspace = await _workspaceRepository.GetBySlugAsync(slug);
        if (workspace == null)
            return NotFound();

        var item = await _itemRepository.GetByIdAsync(itemId, workspace.Id);
        if (item == null)
            return NotFound();

        var collection = await _collectionRepository.GetByIdAsync(item.CollectionId, workspace.Id);
        if (collection == null || !collection.EffectiveIsPublic)
            return NotFound();

        // Compute category visibility if item has a category
        Category? category = null;
        if (item.CategoryId.HasValue)
        {
            var categories = (await _categoryRepository.GetByCollectionAsync(item.CollectionId, workspace.Id)).ToList();
            _visibilityService.ComputeEffectiveVisibility(categories, collection);
            category = categories.FirstOrDefault(c => c.Id == item.CategoryId.Value);
        }

        _visibilityService.ComputeEffectiveVisibility(item, collection, category);

        if (!item.EffectiveIsPublic)
            return NotFound();

        return Ok(new PublicItemDto
        {
            Id = item.Id ?? 0,
            Name = item.Name,
            Summary = item.Summary,
            Description = item.Description,
            Properties = item.Properties.Select(p => new PublicItemPropertyDto
            {
                Category = p.Category,
                Name = p.Name,
                Value = p.Value
            }).ToList(),
            Images = item.Images.Select(img => new PublicItemImageDto
            {
                Url = ToPublicImageUrl(img.Url)!,
                Alt = img.Alt
            }).ToList(),
            CategoryId = item.CategoryId,
            CategoryName = category?.Name,
            TemplateKey = item.TemplateKey
        });
    }

    private static string? ToPublicImageUrl(string? url)
    {
        if (url != null && url.StartsWith("/api/images/") && !url.StartsWith("/api/images/public/"))
            return url.Replace("/api/images/", "/api/images/public/");
        return url;
    }
}
