using Microsoft.AspNetCore.Mvc;
using OneBigHead.Server.Authentication;
using System.Security.Claims;

namespace OneBigHead.Server.Controllers;

/// <summary>
/// Base controller providing workspace-scoped functionality for API controllers.
/// </summary>
/// <remarks>
/// <para>
/// <b>When to use ApiControllerBase:</b>
/// Use this base class for controllers that operate on workspace-scoped data.
/// This includes most domain controllers like Collections, Categories, Items, etc.
/// These controllers require an authenticated user with a valid workspace_id claim.
/// </para>
/// <para>
/// <b>When to use ControllerBase directly:</b>
/// Use the standard ControllerBase for controllers that:
/// <list type="bullet">
///   <item>Handle authentication (AuthController) - operates before workspace context exists</item>
///   <item>Serve system-wide data (ThemesController) - themes are shared across workspaces</item>
///   <item>Handle cross-workspace administration (AdminController, AdminSupportController)</item>
///   <item>Accept both authenticated and anonymous requests (SupportController)</item>
/// </list>
/// </para>
/// </remarks>
[ApiController]
public abstract class ApiControllerBase : ControllerBase
{
    /// <summary>
    /// Extracts and validates the workspace ID from the current user's claims.
    /// </summary>
    /// <returns>The workspace ID from the user's token.</returns>
    /// <exception cref="UnauthorizedAccessException">Thrown when workspace_id claim is missing or invalid.</exception>
    protected int GetWorkspaceId()
    {
        var workspaceIdClaim = User.FindFirst(ClaimNames.WorkspaceId)?.Value;
        if (string.IsNullOrEmpty(workspaceIdClaim) || !int.TryParse(workspaceIdClaim, out var workspaceId))
        {
            throw new UnauthorizedAccessException("Workspace ID not found in token");
        }
        return workspaceId;
    }

    /// <summary>
    /// Attempts to extract the workspace ID from the current user's claims.
    /// </summary>
    /// <returns>The workspace ID if present and valid; otherwise, null.</returns>
    protected int? TryGetWorkspaceId()
    {
        var workspaceIdClaim = User.FindFirst(ClaimNames.WorkspaceId)?.Value;
        if (string.IsNullOrEmpty(workspaceIdClaim) || !int.TryParse(workspaceIdClaim, out var workspaceId))
        {
            return null;
        }
        return workspaceId;
    }

    /// <summary>
    /// Extracts and validates the user ID from the current user's claims.
    /// </summary>
    /// <returns>The user ID from the user's token.</returns>
    /// <exception cref="UnauthorizedAccessException">Thrown when user ID claim is missing or invalid.</exception>
    protected int GetUserId()
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out var userId))
        {
            throw new UnauthorizedAccessException("User ID not found in token");
        }
        return userId;
    }

    /// <summary>
    /// Attempts to extract the user ID from the current user's claims.
    /// </summary>
    /// <returns>The user ID if present and valid; otherwise, null.</returns>
    protected int? TryGetUserId()
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out var userId))
        {
            return null;
        }
        return userId;
    }
}
