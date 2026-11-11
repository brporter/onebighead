using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services.PublicCatalog;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/public")]
[AllowAnonymous]
[EnableRateLimiting("public-read")]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public class PublicController(IPublicCatalogReader catalog) : ControllerBase
{
    [HttpGet("{slug}")]
    public async Task<ActionResult<PublicWorkspaceDto>> GetWorkspaceAsync(string slug)
    {
        var response = await catalog.GetWorkspaceAsync(slug, HttpContext.RequestAborted);
        return response is null ? NotFound() : Ok(response);
    }

    [HttpGet("{slug}/collections")]
    public async Task<ActionResult<List<PublicCollectionDto>>> GetCollectionsAsync(string slug)
    {
        var response = await catalog.GetCollectionsAsync(slug, HttpContext.RequestAborted);
        return response is null ? NotFound() : Ok(response);
    }

    [HttpGet("{slug}/collections/{collectionId:int}")]
    public async Task<ActionResult<PublicCollectionDetailDto>> GetCollectionDetailAsync(string slug, int collectionId)
    {
        var response = await catalog.GetCollectionAsync(slug, collectionId, HttpContext.RequestAborted);
        return response is null ? NotFound() : Ok(response);
    }

    [HttpGet("{slug}/collections/{collectionId:int}/items")]
    public async Task<ActionResult<List<PublicItemSummaryDto>>> GetItemsAsync(string slug, int collectionId, [FromQuery] int? categoryId)
    {
        var response = await catalog.GetItemsAsync(slug, collectionId, categoryId, HttpContext.RequestAborted);
        return response is null ? NotFound() : Ok(response);
    }

    [HttpGet("{slug}/items/{itemId:int}")]
    public async Task<ActionResult<PublicItemDto>> GetItemAsync(string slug, int itemId)
    {
        var response = await catalog.GetItemAsync(slug, itemId, HttpContext.RequestAborted);
        return response is null ? NotFound() : Ok(response);
    }
}
