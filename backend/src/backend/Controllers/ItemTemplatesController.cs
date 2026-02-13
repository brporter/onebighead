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
    /// Gets all templates accessible to the current workspace (system + workspace-owned).
    /// System templates are hidden if a workspace template with the same name exists.
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<IEnumerable<ItemTemplateResponse>>> GetTemplates([FromQuery] string? filter = null)
    {
        var workspaceId = GetWorkspaceId();

        var templates = filter switch
        {
            "system" => await _templateRepository.GetSystemTemplatesAsync(workspaceId),
            "workspace" => await _templateRepository.GetWorkspaceTemplatesAsync(workspaceId),
            _ => await _templateRepository.GetAllAccessibleAsync(workspaceId)
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
        var workspaceId = GetWorkspaceId();

        var template = await _templateRepository.GetByIdAsync(id, workspaceId);
        if (template is null)
        {
            return NotFound();
        }

        return Ok(ItemTemplateResponse.FromItemTemplate(template));
    }

    /// <summary>
    /// Creates a new workspace-owned template.
    /// </summary>
    [HttpPost]
    [Authorize(Policy = "WorkspaceAdmin")]
    public async Task<ActionResult<ItemTemplateResponse>> CreateTemplate(CreateItemTemplateRequest request)
    {
        var workspaceId = GetWorkspaceId();

        var template = request.ToItemTemplate(workspaceId);
        var created = await _templateRepository.CreateAsync(template);

        return CreatedAtAction(
            nameof(GetTemplate), 
            new { id = created.Id }, 
            ItemTemplateResponse.FromItemTemplate(created));
    }

    /// <summary>
    /// Updates a template. For system templates, creates a workspace copy (copy-on-edit).
    /// </summary>
    [HttpPut("{id}")]
    [Authorize(Policy = "WorkspaceAdmin")]
    public async Task<ActionResult<ItemTemplateResponse>> UpdateTemplate(int id, UpdateItemTemplateRequest request)
    {
        var workspaceId = GetWorkspaceId();

        // First check if template exists and is accessible
        var existing = await _templateRepository.GetByIdAsync(id, workspaceId);
        if (existing is null)
        {
            return NotFound();
        }

        var template = request.ToItemTemplate();

        // If it's a system template, copy it to workspace's library instead of editing
        if (existing.WorkspaceId == null)
        {
            var copied = await _templateRepository.CopySystemTemplateAsync(id, workspaceId, template);
            return Ok(ItemTemplateResponse.FromItemTemplate(copied));
        }

        // Otherwise, update the workspace-owned template directly
        var updated = await _templateRepository.UpdateAsync(id, template, workspaceId);
        if (updated is null)
        {
            return NotFound();
        }

        return Ok(ItemTemplateResponse.FromItemTemplate(updated));
    }

    /// <summary>
    /// Deletes a workspace-owned template. System templates cannot be deleted.
    /// </summary>
    [HttpDelete("{id}")]
    [Authorize(Policy = "WorkspaceAdmin")]
    public async Task<IActionResult> DeleteTemplate(int id)
    {
        var workspaceId = GetWorkspaceId();

        var deleted = await _templateRepository.DeleteAsync(id, workspaceId);
        if (!deleted)
        {
            return NotFound();
        }

        return NoContent();
    }
}
