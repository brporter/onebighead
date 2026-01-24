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

    /// <summary>
    /// Gets all templates accessible to the current tenant (shared + tenant-owned).
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<IEnumerable<ItemTemplateResponse>>> GetTemplates([FromQuery] string? filter = null)
    {
        var tenantId = GetTenantId();

        var templates = filter switch
        {
            "shared" => await _templateRepository.GetSharedAsync(),
            "tenant" => await _templateRepository.GetTenantTemplatesAsync(tenantId),
            _ => await _templateRepository.GetAllAccessibleAsync(tenantId)
        };

        var response = templates.Select(t => ItemTemplateResponse.FromItemTemplate(t, tenantId));
        return Ok(response);
    }

    /// <summary>
    /// Gets a specific template by ID.
    /// </summary>
    [HttpGet("{id}")]
    public async Task<ActionResult<ItemTemplateResponse>> GetTemplate(int id)
    {
        var tenantId = GetTenantId();

        var template = await _templateRepository.GetByIdAsync(id, tenantId);
        if (template is null)
        {
            return NotFound();
        }

        return Ok(ItemTemplateResponse.FromItemTemplate(template, tenantId));
    }

    /// <summary>
    /// Creates a new tenant-owned template.
    /// </summary>
    [HttpPost]
    public async Task<ActionResult<ItemTemplateResponse>> CreateTemplate(CreateItemTemplateRequest request)
    {
        var tenantId = GetTenantId();

        var template = request.ToItemTemplate(tenantId);
        var created = await _templateRepository.CreateAsync(template);

        return CreatedAtAction(
            nameof(GetTemplate), 
            new { id = created.Id }, 
            ItemTemplateResponse.FromItemTemplate(created, tenantId));
    }

    /// <summary>
    /// Updates an existing tenant-owned template. Shared templates cannot be edited.
    /// </summary>
    [HttpPut("{id}")]
    public async Task<ActionResult<ItemTemplateResponse>> UpdateTemplate(int id, UpdateItemTemplateRequest request)
    {
        var tenantId = GetTenantId();

        var template = request.ToItemTemplate();
        var updated = await _templateRepository.UpdateAsync(id, template, tenantId);
        
        if (updated is null)
        {
            return NotFound();
        }

        return Ok(ItemTemplateResponse.FromItemTemplate(updated, tenantId));
    }

    /// <summary>
    /// Deletes a tenant-owned template. Shared templates cannot be deleted.
    /// </summary>
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteTemplate(int id)
    {
        var tenantId = GetTenantId();

        var deleted = await _templateRepository.DeleteAsync(id, tenantId);
        if (!deleted)
        {
            return NotFound();
        }

        return NoContent();
    }
}
