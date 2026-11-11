using OneBigHead.Server.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OneBigHead.Server.Services.Templates;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Services.Administration;
using OneBigHead.Server.Middleware;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = SystemAdministratorRequirement.PolicyName)]
[AllowInactiveWorkspace]
public class AdminController : ControllerBase
{
    private readonly IAdministratorWorkspaceDeletion _workspaceDeletion;
    private readonly ISystemTemplateService _templates;
    private readonly IAdministratorDirectory _directory;
    private readonly IAdministratorUsers _users;

    public AdminController(IAdministratorWorkspaceDeletion workspaceDeletion, ISystemTemplateService templates, IAdministratorDirectory directory, IAdministratorUsers users)
    {
        _workspaceDeletion = workspaceDeletion;
        _templates = templates;
        _directory = directory;
        _users = users;
    }

    /// <summary>
    /// Gets all workspaces with usage statistics.
    /// </summary>
    [HttpGet("workspaces")]
    public async Task<ActionResult<IEnumerable<WorkspaceSummaryResponse>>> GetWorkspaces() =>
        Ok(await _directory.GetWorkspacesAsync());

    /// <summary>
    /// Deletes a workspace and all associated data.
    /// </summary>
    [HttpDelete("workspaces/{id}")]
    public async Task<IActionResult> DeleteWorkspace(int id) => await _workspaceDeletion.DeleteAsync(id) switch
    {
        AdministratorWorkspaceDeletionResult.Deleted => NoContent(),
        AdministratorWorkspaceDeletionResult.NotFound => NotFound(),
        AdministratorWorkspaceDeletionResult.ConcurrentChange => Conflict(new { error = "The workspace changed while deleting. Reload and try again." }),
        _ => Conflict(new { error = "This workspace has references from other workspaces or shared themes. Resolve those references before deleting it." })
    };

    /// <summary>
    /// Gets all users, optionally filtered by email.
    /// </summary>
    [HttpGet("users")]
    public async Task<ActionResult<IEnumerable<UserSummaryResponse>>> GetUsers([FromQuery] string? email = null) =>
        Ok(await _directory.GetUsersAsync(email));

    /// <summary>
    /// Deletes a user.
    /// </summary>
    [HttpDelete("users/{id}")]
    public async Task<IActionResult> DeleteUser(int id) =>
        await _users.DeleteAsync(id) ? NoContent() : NotFound();

    /// <summary>
    /// Sets the system administrator status for a user.
    /// </summary>
    [HttpPut("users/{id}/admin")]
    public async Task<ActionResult<UserSummaryResponse>> SetAdminStatus(int id, SetAdminStatusRequest request)
    {
        var user = await _users.SetAdministratorAsync(id, request.IsSystemAdministrator);
        return user is null ? NotFound() : Ok(user);
    }

    [HttpGet("templates")]
    public async Task<ActionResult<IEnumerable<ItemTemplateResponse>>> GetSystemTemplates() =>
        Ok(await _templates.GetAllAsync());

    [HttpPost("templates")]
    public async Task<ActionResult<ItemTemplateResponse>> CreateSystemTemplate(SystemTemplateRequest request)
    {
        var template = await _templates.CreateAsync(request);
        return CreatedAtAction(nameof(GetSystemTemplate), new { id = template.ItemTemplateId }, template);
    }

    [HttpGet("templates/{id}")]
    public async Task<ActionResult<ItemTemplateResponse>> GetSystemTemplate(int id)
    {
        var template = await _templates.GetAsync(id);
        return template is null ? NotFound() : Ok(template);
    }

    [HttpPut("templates/{id}")]
    public async Task<ActionResult<ItemTemplateResponse>> UpdateSystemTemplate(int id, SystemTemplateRequest request)
    {
        var template = await _templates.UpdateAsync(id, request);
        return template is null ? NotFound() : Ok(template);
    }

    [HttpDelete("templates/{id}")]
    public async Task<IActionResult> DeleteSystemTemplate(int id) =>
        await _templates.DeleteAsync(id) ? NoContent() : NotFound();
}
