using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services.Templates;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ItemTemplatesController : ApiControllerBase
{
    private readonly IItemTemplateRepository _templateRepository;
    private readonly IWorkspaceTemplateEditor _editor;

    public ItemTemplatesController(IItemTemplateRepository templateRepository, IWorkspaceTemplateEditor editor)
    {
        _templateRepository = templateRepository;
        _editor = editor;
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
        var created = await _editor.CreateAsync(GetWorkspaceId(), request);
        return CreatedAtAction(nameof(GetTemplate), new { id = created.Id }, ItemTemplateResponse.FromItemTemplate(created));
    }

    [HttpPut("{id}")]
    [Authorize(Policy = "WorkspaceAdmin")]
    public async Task<ActionResult<ItemTemplateResponse>> UpdateTemplate(int id, UpdateItemTemplateRequest request)
    {
        var updated = await _editor.UpdateAsync(GetWorkspaceId(), id, request);
        return updated is null ? NotFound() : Ok(ItemTemplateResponse.FromItemTemplate(updated));
    }

    [HttpDelete("{id}")]
    [Authorize(Policy = "WorkspaceAdmin")]
    public async Task<IActionResult> DeleteTemplate(int id) =>
        await _editor.DeleteAsync(GetWorkspaceId(), id) ? NoContent() : NotFound();
}
