using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/collections/{collectionId}/property-suggestions")]
[Authorize]
public class PropertySuggestionsController : ApiControllerBase
{
    private readonly IPropertySuggestionRepository _suggestionRepository;
    private readonly ICollectionRepository _collectionRepository;

    public PropertySuggestionsController(
        IPropertySuggestionRepository suggestionRepository,
        ICollectionRepository collectionRepository)
    {
        _suggestionRepository = suggestionRepository;
        _collectionRepository = collectionRepository;
    }

    /// <summary>
    /// Get all property suggestions for a collection
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<PropertySuggestionsResponse>> GetSuggestions(int collectionId)
    {
        var tenantId = GetTenantId();

        // Verify collection belongs to tenant
        var collection = await _collectionRepository.GetByIdAsync(collectionId, tenantId);
        if (collection is null)
        {
            return NotFound("Collection not found");
        }

        var categories = await _suggestionRepository.GetCategoriesAsync(collectionId, tenantId);
        var names = await _suggestionRepository.GetNamesAsync(collectionId, tenantId);

        return Ok(new PropertySuggestionsResponse
        {
            Categories = categories.ToList(),
            Names = names.ToList()
        });
    }

    /// <summary>
    /// Sync property suggestions for a collection based on current items.
    /// This recalculates which suggestions should exist based on the properties 
    /// actually used by items in the collection.
    /// </summary>
    [HttpPost("sync")]
    public async Task<ActionResult<PropertySuggestionsResponse>> SyncSuggestions(int collectionId)
    {
        var tenantId = GetTenantId();

        // Verify collection belongs to tenant
        var collection = await _collectionRepository.GetByIdAsync(collectionId, tenantId);
        if (collection is null)
        {
            return NotFound("Collection not found");
        }

        // Sync suggestions based on current items
        await _suggestionRepository.SyncSuggestionsAsync(collectionId, tenantId, [], []);

        // Return the updated suggestions
        var categories = await _suggestionRepository.GetCategoriesAsync(collectionId, tenantId);
        var names = await _suggestionRepository.GetNamesAsync(collectionId, tenantId);

        return Ok(new PropertySuggestionsResponse
        {
            Categories = categories.ToList(),
            Names = names.ToList()
        });
    }
}
