using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ItemTemplatesController : ApiControllerBase
{
    private readonly IItemTemplateRepository _templateRepository;

    public ItemTemplatesController(IItemTemplateRepository templateRepository)
    {
        _templateRepository = templateRepository;
    }

    /// <summary>
    /// Gets all templates accessible to the current tenant (system + tenant-owned).
    /// System templates are hidden if a tenant template with the same name exists.
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<IEnumerable<ItemTemplateResponse>>> GetTemplates([FromQuery] string? filter = null)
    {
        var tenantId = GetTenantId();

        var templates = filter switch
        {
            "system" => await _templateRepository.GetSystemTemplatesAsync(tenantId),
            "tenant" => await _templateRepository.GetTenantTemplatesAsync(tenantId),
            _ => await _templateRepository.GetAllAccessibleAsync(tenantId)
        };

        var response = templates.Select(ItemTemplateResponse.FromItemTemplate);
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

        return Ok(ItemTemplateResponse.FromItemTemplate(template));
    }

    /// <summary>
    /// Creates a new tenant-owned template.
    /// </summary>
    [HttpPost]
    [Authorize(Policy = "TenantAdmin")]
    public async Task<ActionResult<ItemTemplateResponse>> CreateTemplate(CreateItemTemplateRequest request)
    {
        var tenantId = GetTenantId();

        var template = request.ToItemTemplate(tenantId);
        var created = await _templateRepository.CreateAsync(template);

        return CreatedAtAction(
            nameof(GetTemplate), 
            new { id = created.Id }, 
            ItemTemplateResponse.FromItemTemplate(created));
    }

    /// <summary>
    /// Updates a template. For system templates, creates a tenant copy (copy-on-edit).
    /// </summary>
    [HttpPut("{id}")]
    [Authorize(Policy = "TenantAdmin")]
    public async Task<ActionResult<ItemTemplateResponse>> UpdateTemplate(int id, UpdateItemTemplateRequest request)
    {
        var tenantId = GetTenantId();

        // First check if template exists and is accessible
        var existing = await _templateRepository.GetByIdAsync(id, tenantId);
        if (existing is null)
        {
            return NotFound();
        }

        var template = request.ToItemTemplate();

        // If it's a system template, copy it to tenant's library instead of editing
        if (existing.TenantId == null)
        {
            var copied = await _templateRepository.CopySystemTemplateAsync(id, tenantId, template);
            return Ok(ItemTemplateResponse.FromItemTemplate(copied));
        }

        // Otherwise, update the tenant-owned template directly
        var updated = await _templateRepository.UpdateAsync(id, template, tenantId);
        if (updated is null)
        {
            return NotFound();
        }

        return Ok(ItemTemplateResponse.FromItemTemplate(updated));
    }

    /// <summary>
    /// Deletes a tenant-owned template. System templates cannot be deleted.
    /// </summary>
    [HttpDelete("{id}")]
    [Authorize(Policy = "TenantAdmin")]
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
