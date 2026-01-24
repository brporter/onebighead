using backend.Data;
using backend.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace backend.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ItemTemplatesController : ControllerBase
{
    private readonly IItemTemplateRepository _templateRepository;

    public ItemTemplatesController(IItemTemplateRepository templateRepository)
    {
        _templateRepository = templateRepository;
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

    /// <summary>
    /// Gets all templates accessible to the current user (shared + personal).
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<IEnumerable<ItemTemplateResponse>>> GetTemplates([FromQuery] string? filter = null)
    {
        var tenantId = GetTenantId();
        var userId = GetUserId();

        var templates = filter switch
        {
            "shared" => await _templateRepository.GetSharedAsync(),
            "personal" => await _templateRepository.GetPersonalAsync(tenantId, userId),
            _ => await _templateRepository.GetAllAccessibleAsync(tenantId, userId)
        };

        var response = templates.Select(t => ItemTemplateResponse.FromItemTemplate(t, userId));
        return Ok(response);
    }

    /// <summary>
    /// Gets a specific template by ID.
    /// </summary>
    [HttpGet("{id}")]
    public async Task<ActionResult<ItemTemplateResponse>> GetTemplate(int id)
    {
        var tenantId = GetTenantId();
        var userId = GetUserId();

        var template = await _templateRepository.GetByIdAsync(id, tenantId, userId);
        if (template is null)
        {
            return NotFound();
        }

        return Ok(ItemTemplateResponse.FromItemTemplate(template, userId));
    }

    /// <summary>
    /// Creates a new personal template for the current user.
    /// </summary>
    [HttpPost]
    public async Task<ActionResult<ItemTemplateResponse>> CreateTemplate(CreateItemTemplateRequest request)
    {
        var tenantId = GetTenantId();
        var userId = GetUserId();

        var template = request.ToItemTemplate(tenantId, userId);
        var created = await _templateRepository.CreateAsync(template);

        return CreatedAtAction(
            nameof(GetTemplate), 
            new { id = created.Id }, 
            ItemTemplateResponse.FromItemTemplate(created, userId));
    }

    /// <summary>
    /// Updates an existing personal template owned by the current user.
    /// </summary>
    [HttpPut("{id}")]
    public async Task<ActionResult<ItemTemplateResponse>> UpdateTemplate(int id, UpdateItemTemplateRequest request)
    {
        var tenantId = GetTenantId();
        var userId = GetUserId();

        var template = request.ToItemTemplate();
        var updated = await _templateRepository.UpdateAsync(id, template, tenantId, userId);
        
        if (updated is null)
        {
            return NotFound();
        }

        return Ok(ItemTemplateResponse.FromItemTemplate(updated, userId));
    }

    /// <summary>
    /// Deletes a personal template owned by the current user.
    /// </summary>
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteTemplate(int id)
    {
        var tenantId = GetTenantId();
        var userId = GetUserId();

        var deleted = await _templateRepository.DeleteAsync(id, tenantId, userId);
        if (!deleted)
        {
            return NotFound();
        }

        return NoContent();
    }
}
