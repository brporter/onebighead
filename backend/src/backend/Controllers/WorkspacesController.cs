using OneBigHead.Server.Middleware;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Workspaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OneBigHead.Server.Controllers;

[Route("api/[controller]")]
[Authorize]
public class WorkspacesController : ApiControllerBase
{
    private readonly IWorkspaceRepository _workspaceRepository;
    private readonly IWorkspaceUserRepository _workspaceUserRepository;
    private readonly IWorkspaceSummaryService _workspaceSummary;

    public WorkspacesController(IWorkspaceRepository workspaceRepository,
        IWorkspaceUserRepository workspaceUserRepository, IWorkspaceSummaryService workspaceSummary)
    {
        _workspaceRepository = workspaceRepository;
        _workspaceUserRepository = workspaceUserRepository;
        _workspaceSummary = workspaceSummary;
    }

    /// <summary>
    /// List all workspace memberships for the current user
    /// </summary>
    [AllowInactiveWorkspace]
    [HttpGet]
    public async Task<IActionResult> GetWorkspaces()
    {
        var userId = GetUserId();
        var memberships = await _workspaceUserRepository.GetByUserIdAsync(userId);

        // Filter out deleted workspaces
        var response = memberships
            .Where(m => m.Workspace != null && !m.Workspace.IsDeleted)
            .Select(m => new WorkspaceMembershipResponse
            {
                WorkspaceId = m.WorkspaceId,
                WorkspaceName = m.Workspace!.Name,
                WorkspaceRole = m.WorkspaceRole,
                HasCompletedWelcome = m.Workspace.HasCompletedWelcome
            }).ToList();

        return Ok(response);
    }

    /// <summary>
    /// Get deletion statistics for a workspace (requires WorkspaceAdmin role)
    /// </summary>
    [HttpGet("{workspaceId}/stats")]
    public async Task<IActionResult> GetWorkspaceStats(int workspaceId)
    {
        var userId = GetUserId();

        // Verify user is a member of this workspace and has WorkspaceAdmin role
        var membership = await _workspaceUserRepository.GetMembershipAsync(userId, workspaceId);
        if (membership == null)
        {
            return NotFound(new { error = "Workspace not found" });
        }

        if (membership.WorkspaceRole != WorkspaceRole.WorkspaceAdmin)
        {
            return Forbid();
        }

        var stats = await _workspaceSummary.GetWorkspaceStatsAsync(workspaceId);
        if (stats == null)
        {
            return NotFound(new { error = "Workspace not found" });
        }

        return Ok(stats);
    }

    /// <summary>
    /// Check if a workspace slug is available
    /// </summary>
    [HttpGet("check-slug/{slug}")]
    public async Task<IActionResult> CheckSlugAsync(string slug)
    {
        var slugTaken = await _workspaceRepository.IsSlugTakenAsync(slug);
        return Ok(new CheckSlugResponse { IsAvailable = !slugTaken });
    }

}
