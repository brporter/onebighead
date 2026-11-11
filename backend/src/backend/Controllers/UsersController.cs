using OneBigHead.Server.Middleware;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class UsersController : ApiControllerBase
{
    private readonly IWorkspaceUserRepository _workspaceUserRepository;
    private readonly IWorkspaceRepository _workspaceRepository;

    public UsersController(
        IWorkspaceUserRepository workspaceUserRepository,
        IWorkspaceRepository workspaceRepository)
    {
        _workspaceUserRepository = workspaceUserRepository;
        _workspaceRepository = workspaceRepository;
    }

    /// <summary>
    /// Get soft-deleted workspaces that the current user can restore.
    /// Only returns workspaces where user was WorkspaceAdmin.
    /// </summary>
    [AllowInactiveWorkspace]
    [HttpGet("me/restorable-workspaces")]
    public async Task<IActionResult> GetRestorableWorkspaces()
    {
        var userId = GetUserId();

        // Get all workspace memberships for this user where they are WorkspaceAdmin
        var adminMemberships = await _workspaceUserRepository.GetAdminMembershipsIncludingDeletedAsync(userId);

        // Filter to only deleted workspaces and build response
        var restorableWorkspaces = new List<RestorableWorkspaceResponse>();
        foreach (var membership in adminMemberships)
        {
            if (membership.Workspace == null || !membership.Workspace.IsDeleted)
            {
                continue;
            }

            var stats = await _workspaceRepository.GetStatsAsync(membership.WorkspaceId);

            restorableWorkspaces.Add(new RestorableWorkspaceResponse
            {
                WorkspaceId = membership.WorkspaceId,
                Name = membership.Workspace.Name,
                DeletedAt = membership.Workspace.DeletedAt!.Value,
                DaysRemaining = Math.Max(0, 30 - (DateTime.UtcNow - membership.Workspace.DeletedAt!.Value).Days),
                Stats = new RestorableWorkspaceStats
                {
                    CollectionCount = stats.CollectionCount,
                    ItemCount = stats.ItemCount,
                    CategoryCount = stats.CategoryCount,
                    ImageCount = stats.ImageCount
                }
            });
        }

        return Ok(restorableWorkspaces);
    }

}
