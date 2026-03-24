using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Extensions;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services;
using OneBigHead.Server.Utilities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace OneBigHead.Server.Controllers;

[Route("api/[controller]")]
[Authorize]
public class WorkspacesController : ApiControllerBase
{
    private readonly IWorkspaceRepository _workspaceRepository;
    private readonly IWorkspaceUserRepository _workspaceUserRepository;
    private readonly IUserRepository _userRepository;
    private readonly ICollectionRepository _collectionRepository;
    private readonly ICategoryRepository _categoryRepository;
    private readonly IItemTemplateRepository _itemTemplateRepository;
    private readonly IThemeRepository _themeRepository;
    private readonly ITokenService _tokenService;
    private readonly IWorkspaceService _workspaceService;
    private readonly AuthenticationSettings _settings;
    private readonly ILogger<WorkspacesController> _logger;

    public WorkspacesController(
        IWorkspaceRepository workspaceRepository,
        IWorkspaceUserRepository workspaceUserRepository,
        IUserRepository userRepository,
        ICollectionRepository collectionRepository,
        ICategoryRepository categoryRepository,
        IItemTemplateRepository itemTemplateRepository,
        IThemeRepository themeRepository,
        ITokenService tokenService,
        IWorkspaceService workspaceService,
        IOptions<AuthenticationSettings> settings,
        ILogger<WorkspacesController> logger)
    {
        _workspaceRepository = workspaceRepository;
        _workspaceUserRepository = workspaceUserRepository;
        _userRepository = userRepository;
        _collectionRepository = collectionRepository;
        _categoryRepository = categoryRepository;
        _itemTemplateRepository = itemTemplateRepository;
        _themeRepository = themeRepository;
        _tokenService = tokenService;
        _workspaceService = workspaceService;
        _settings = settings.Value;
        _logger = logger;
    }

    /// <summary>
    /// List all workspace memberships for the current user
    /// </summary>
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
    /// Create a new workspace and add the current user as WorkspaceAdmin.
    /// Note: This creates a workspace without a collection. For full setup with collection, use SetupWorkspace.
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> CreateWorkspace([FromBody] CreateWorkspaceRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest(new { error = "Workspace name is required" });
        }

        var userId = GetUserId();

        // Create the new workspace
        var workspace = new Workspace
        {
            Name = request.Name.Trim(),
            HasCompletedWelcome = false,
            CreatedAt = DateTime.UtcNow
        };

        await _workspaceRepository.CreateAsync(workspace);

        // Add user as WorkspaceAdmin of the new workspace
        await _workspaceUserRepository.CreateAsync(userId, workspace.Id, WorkspaceRole.WorkspaceAdmin);

        _logger.LogInformation("User {UserId} created new workspace {WorkspaceId} ({WorkspaceName})", userId, workspace.Id, workspace.Name);

        return Ok(new CreateWorkspaceResponse
        {
            WorkspaceId = workspace.Id,
            WorkspaceName = workspace.Name,
            WorkspaceRole = WorkspaceRole.WorkspaceAdmin,
            HasCompletedWelcome = false
        });
    }

    /// <summary>
    /// Set up a new workspace with an initial collection.
    /// This is the recommended way to create a new workspace as it includes all necessary setup.
    /// </summary>
    [HttpPost("setup")]
    public async Task<IActionResult> SetupWorkspace([FromBody] SetupWorkspaceRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.WorkspaceName))
        {
            return BadRequest(new { error = "Workspace name is required" });
        }

        var userId = GetUserId();

        // Create the new workspace
        var workspace = new Workspace
        {
            Name = request.WorkspaceName.Trim(),
            HasCompletedWelcome = true, // Mark as complete since we're setting up fully
            CreatedAt = DateTime.UtcNow
        };

        await _workspaceRepository.CreateAsync(workspace);

        // Add user as WorkspaceAdmin of the new workspace
        await _workspaceUserRepository.CreateAsync(userId, workspace.Id, WorkspaceRole.WorkspaceAdmin);

        _logger.LogInformation("User {UserId} created new workspace {WorkspaceId} ({WorkspaceName}) via setup", userId, workspace.Id, workspace.Name);

        // Determine collection name (default if not provided)
        var collectionName = string.IsNullOrWhiteSpace(request.CollectionName)
            ? Constants.CollectionNames.MyCollection
            : request.CollectionName.Trim();

        // Get the theme (default to General if not provided or invalid)
        CollectionTheme? theme = null;
        if (request.ThemeId.HasValue)
        {
            theme = await _themeRepository.GetByIdAsync(request.ThemeId.Value);
        }
        if (theme == null)
        {
            // Find the General theme as default
            var themes = await _themeRepository.GetAllAsync();
            theme = themes.FirstOrDefault(t => t.Name == Constants.ThemeNames.General) ?? themes.FirstOrDefault();
        }

        // Create the collection
        var slug = SlugHelper.GenerateSlug(collectionName);
        var existing = await _collectionRepository.GetBySlugAsync(slug, workspace.Id);
        if (existing != null)
        {
            slug = $"{slug}-{DateTime.UtcNow.Ticks}";
        }

        var collection = new Collection
        {
            WorkspaceId = workspace.Id,
            Name = collectionName,
            Description = request.CollectionDescription?.Trim() ?? string.Empty,
            Slug = slug,
            Visibility = Visibility.Private
        };

        var createdCollection = await _collectionRepository.CreateAsync(collection);

        // Create "Unassigned Items" system category
        var unassignedCategory = new Category
        {
            WorkspaceId = workspace.Id,
            CollectionId = createdCollection.Id,
            Name = Constants.CategoryNames.UnassignedItems,
            Description = Constants.CategoryNames.UnassignedItemsDescription,
            IsSystem = true
        };
        await _categoryRepository.CreateAsync(unassignedCategory);

        // Apply theme if available
        if (theme != null)
        {
            // Associate theme templates with collection
            foreach (var themeTemplate in theme.ThemeTemplates)
            {
                await _itemTemplateRepository.AssociateWithCollectionAsync(themeTemplate.ItemTemplateId, createdCollection.Id);
            }

            // Create categories from theme
            await CreateThemeCategoriesAsync(theme, workspace.Id, createdCollection.Id);
        }

        _logger.LogInformation("Created collection {CollectionId} ({CollectionName}) for new workspace {WorkspaceId}",
            createdCollection.Id, createdCollection.Name, workspace.Id);

        // Switch user to the new workspace
        await _userRepository.UpdateActiveWorkspaceAsync(userId, workspace.Id);

        // Generate new JWT with the new workspace
        var user = await _userRepository.GetByIdAsync(userId);
        if (user != null)
        {
            var appToken = _tokenService.GenerateAppToken(user, WorkspaceRole.WorkspaceAdmin);
            Response.SetAuthCookie(appToken, _settings);
        }

        return Ok(new SetupWorkspaceResponse
        {
            WorkspaceId = workspace.Id,
            WorkspaceName = workspace.Name,
            WorkspaceRole = WorkspaceRole.WorkspaceAdmin,
            CollectionId = createdCollection.Id,
            CollectionName = createdCollection.Name
        });
    }

    private async Task CreateThemeCategoriesAsync(CollectionTheme theme, int workspaceId, int collectionId)
    {
        if (theme.ThemeCategories == null || !theme.ThemeCategories.Any())
            return;

        // Map theme category names to created category IDs
        var categoryNameToIdMap = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        // Sort by parent to ensure parents are created first
        // Use iterative approach to handle arbitrary nesting depth
        var pendingCategories = theme.ThemeCategories.OrderBy(c => c.SortOrder).ToList();
        var maxIterations = pendingCategories.Count * 2; // Safety limit
        var iterations = 0;

        while (pendingCategories.Count > 0 && iterations < maxIterations)
        {
            iterations++;
            var categoriesToProcess = pendingCategories
                .Where(tc => string.IsNullOrEmpty(tc.ParentName) || categoryNameToIdMap.ContainsKey(tc.ParentName))
                .ToList();

            if (!categoriesToProcess.Any())
            {
                _logger.LogWarning("Theme {ThemeId} has orphaned categories that couldn't be created", theme.Id);
                break;
            }

            foreach (var themeCategory in categoriesToProcess)
            {
                int? parentCategoryId = null;
                if (!string.IsNullOrEmpty(themeCategory.ParentName) && categoryNameToIdMap.TryGetValue(themeCategory.ParentName, out var parentId))
                {
                    parentCategoryId = parentId;
                }

                var category = new Category
                {
                    WorkspaceId = workspaceId,
                    CollectionId = collectionId,
                    ParentCategoryId = parentCategoryId,
                    Name = themeCategory.Name,
                    Description = themeCategory.Description ?? string.Empty,
                    IsSystem = false
                };

                var created = await _categoryRepository.CreateAsync(category);
                categoryNameToIdMap[themeCategory.Name] = created.Id;
                pendingCategories.Remove(themeCategory);
            }
        }
    }

    /// <summary>
    /// Update a workspace's details (requires WorkspaceAdmin role)
    /// </summary>
    [HttpPut("{workspaceId}")]
    public async Task<IActionResult> UpdateWorkspace(int workspaceId, [FromBody] UpdateWorkspaceRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest(new { error = "Workspace name is required" });
        }

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

        // Get and update the workspace
        var workspace = await _workspaceRepository.GetByIdAsync(workspaceId);
        if (workspace == null)
        {
            return NotFound(new { error = "Workspace not found" });
        }

        // Validate slug if provided
        if (!string.IsNullOrEmpty(request.Slug))
        {
            var slugTaken = await _workspaceRepository.IsSlugTakenAsync(request.Slug, excludeWorkspaceId: workspaceId);
            if (slugTaken)
            {
                return Conflict(new { error = "This slug is already taken" });
            }
        }

        workspace.Name = request.Name.Trim();
        workspace.Slug = request.Slug;
        await _workspaceRepository.UpdateAsync(workspace);

        _logger.LogInformation("User {UserId} updated workspace {WorkspaceId} name to {WorkspaceName}", userId, workspaceId, workspace.Name);

        return Ok(new UpdateWorkspaceResponse
        {
            WorkspaceId = workspace.Id,
            WorkspaceName = workspace.Name,
            Slug = workspace.Slug,
            PublicUrl = !string.IsNullOrEmpty(workspace.Slug) ? $"/public/{workspace.Slug}" : null
        });
    }

    /// <summary>
    /// Switch the current user's active workspace
    /// </summary>
    [HttpPost("{workspaceId}/switch")]
    public async Task<IActionResult> SwitchWorkspace(int workspaceId)
    {
        var userId = GetUserId();

        // Verify user is a member of the target workspace
        var membership = await _workspaceUserRepository.GetMembershipAsync(userId, workspaceId);
        if (membership == null)
        {
            return Forbid();
        }

        // Update user's active workspace
        await _userRepository.UpdateActiveWorkspaceAsync(userId, workspaceId);

        // Get updated user and generate new token
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            return NotFound(new { error = "User not found" });
        }

        // Generate new JWT with updated workspace
        var appToken = _tokenService.GenerateAppToken(user, membership.WorkspaceRole);
        Response.SetAuthCookie(appToken, _settings);

        _logger.LogInformation("User {UserId} switched to workspace {WorkspaceId}", userId, workspaceId);

        return Ok(new SwitchWorkspaceResponse
        {
            Success = true,
            WorkspaceId = workspaceId,
            WorkspaceName = membership.Workspace.Name
        });
    }

    /// <summary>
    /// Leave a workspace (remove membership)
    /// </summary>
    [HttpDelete("{workspaceId}/membership")]
    public async Task<IActionResult> LeaveWorkspace(int workspaceId)
    {
        var userId = GetUserId();

        // Verify user is a member of this workspace
        var membership = await _workspaceUserRepository.GetMembershipAsync(userId, workspaceId);
        if (membership == null)
        {
            return NotFound(new { error = "You are not a member of this workspace" });
        }

        // Check if this is the user's only workspace
        var membershipCount = await _workspaceUserRepository.CountUserMembershipsAsync(userId);
        if (membershipCount <= 1)
        {
            return BadRequest(new { error = "Cannot leave your only workspace" });
        }

        // If user is WorkspaceAdmin, check if there are other admins
        if (membership.WorkspaceRole == WorkspaceRole.WorkspaceAdmin)
        {
            var adminCount = await _workspaceUserRepository.CountAdminsInWorkspaceAsync(workspaceId);
            if (adminCount <= 1)
            {
                return BadRequest(new { error = "Cannot leave: you are the only admin in this workspace. Promote another user to admin first." });
            }
        }

        // Get user's current active workspace
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            return NotFound(new { error = "User not found" });
        }

        var wasActiveWorkspace = user.ActiveWorkspaceId == workspaceId;

        // Remove membership
        await _workspaceUserRepository.DeleteAsync(userId, workspaceId);

        _logger.LogInformation("User {UserId} left workspace {WorkspaceId}", userId, workspaceId);

        // If this was their active workspace, we need to switch to another
        if (wasActiveWorkspace)
        {
            var remainingMemberships = await _workspaceUserRepository.GetByUserIdAsync(userId);
            var nextWorkspace = remainingMemberships.FirstOrDefault();
            if (nextWorkspace != null)
            {
                await _userRepository.UpdateActiveWorkspaceAsync(userId, nextWorkspace.WorkspaceId);

                // Reload user and generate new token
                user = await _userRepository.GetByIdAsync(userId);
                if (user != null)
                {
                    var appToken = _tokenService.GenerateAppToken(user, nextWorkspace.WorkspaceRole);
                    Response.SetAuthCookie(appToken, _settings);
                }
            }
        }

        return Ok(new LeaveWorkspaceResponse { Success = true });
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

        var stats = await _workspaceService.GetWorkspaceStatsAsync(workspaceId);
        if (stats == null)
        {
            return NotFound(new { error = "Workspace not found" });
        }

        return Ok(stats);
    }

    /// <summary>
    /// Soft-delete a workspace (requires WorkspaceAdmin role)
    /// </summary>
    [HttpDelete("{workspaceId}")]
    public async Task<IActionResult> DeleteWorkspace(int workspaceId)
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

        var result = await _workspaceService.SoftDeleteWorkspaceAsync(workspaceId, userId);
        if (!result.Success)
        {
            return BadRequest(new { error = "Failed to delete workspace" });
        }

        // If user was switched to another workspace, update their token
        if (result.NewActiveWorkspaceId.HasValue)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            var newMembership = await _workspaceUserRepository.GetMembershipAsync(userId, result.NewActiveWorkspaceId.Value);
            if (user != null && newMembership != null)
            {
                var appToken = _tokenService.GenerateAppToken(user, newMembership.WorkspaceRole);
                Response.SetAuthCookie(appToken, _settings);
            }
        }

        return Ok(result);
    }

    /// <summary>
    /// Restore multiple soft-deleted workspaces (requires user was WorkspaceAdmin of each).
    /// User identity is determined from JWT claims only.
    /// </summary>
    [HttpPost("restore")]
    public async Task<IActionResult> RestoreWorkspaces([FromBody] RestoreWorkspacesRequest request)
    {
        var userId = GetUserId();

        if (request.WorkspaceIds == null || !request.WorkspaceIds.Any())
        {
            return BadRequest(new { error = "At least one workspace ID is required" });
        }

        var restoredIds = new List<int>();
        int? firstActiveWorkspaceId = null;

        foreach (var workspaceId in request.WorkspaceIds)
        {
            // Verify user was WorkspaceAdmin of this workspace
            var membership = await _workspaceUserRepository.GetMembershipAsync(userId, workspaceId);
            if (membership == null || membership.WorkspaceRole != WorkspaceRole.WorkspaceAdmin)
            {
                return Forbid(); // User wasn't admin of this workspace
            }

            var workspace = await _workspaceRepository.GetByIdAsync(workspaceId);
            if (workspace == null || !workspace.IsDeleted)
            {
                continue; // Skip non-existent or already-active workspaces
            }

            // Restore the workspace
            workspace.IsDeleted = false;
            workspace.DeletedAt = null;
            workspace.DeletedByUserId = null;
            await _workspaceRepository.UpdateAsync(workspace);

            restoredIds.Add(workspaceId);
            if (!firstActiveWorkspaceId.HasValue)
            {
                firstActiveWorkspaceId = workspaceId;
            }

            _logger.LogInformation("User {UserId} restored workspace {WorkspaceId} ({WorkspaceName})",
                userId, workspaceId, workspace.Name);
        }

        // Set the first restored workspace as active
        if (firstActiveWorkspaceId.HasValue)
        {
            await _userRepository.UpdateActiveWorkspaceAsync(userId, firstActiveWorkspaceId.Value);

            // Generate new JWT with the new workspace
            var user = await _userRepository.GetByIdAsync(userId);
            if (user != null)
            {
                var appToken = _tokenService.GenerateAppToken(user, WorkspaceRole.WorkspaceAdmin);
                Response.SetAuthCookie(appToken, _settings);
            }
        }

        return Ok(new RestoreWorkspacesResponse
        {
            RestoredWorkspaceIds = restoredIds,
            ActiveWorkspaceId = firstActiveWorkspaceId ?? 0
        });
    }

    /// <summary>
    /// Restore a single soft-deleted workspace (requires user was WorkspaceAdmin).
    /// </summary>
    [HttpPost("{workspaceId}/restore")]
    public async Task<IActionResult> RestoreWorkspace(int workspaceId)
    {
        var userId = GetUserId();

        // Verify user was WorkspaceAdmin of this workspace
        var membership = await _workspaceUserRepository.GetMembershipAsync(userId, workspaceId);
        if (membership == null || membership.WorkspaceRole != WorkspaceRole.WorkspaceAdmin)
        {
            return Forbid();
        }

        var workspace = await _workspaceRepository.GetByIdAsync(workspaceId);
        if (workspace == null)
        {
            return NotFound(new { error = "Workspace not found" });
        }

        if (!workspace.IsDeleted)
        {
            return BadRequest(new { error = "Workspace is not deleted" });
        }

        // Restore the workspace
        workspace.IsDeleted = false;
        workspace.DeletedAt = null;
        workspace.DeletedByUserId = null;
        await _workspaceRepository.UpdateAsync(workspace);

        _logger.LogInformation("User {UserId} restored workspace {WorkspaceId} ({WorkspaceName})",
            userId, workspaceId, workspace.Name);

        return Ok(new RestoreWorkspaceResponse
        {
            WorkspaceId = workspace.Id,
            Name = workspace.Name
        });
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

    /// <summary>
    /// Transfer admin role to another user (requires WorkspaceAdmin role)
    /// </summary>
    [HttpPost("{workspaceId}/transfer-admin")]
    public async Task<IActionResult> TransferAdmin(int workspaceId, [FromBody] TransferAdminRequest request)
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

        // Verify target user is a member of this workspace
        var targetMembership = await _workspaceUserRepository.GetMembershipAsync(request.NewAdminUserId, workspaceId);
        if (targetMembership == null)
        {
            return BadRequest(new { error = "Target user is not a member of this workspace" });
        }

        // Promote target user and demote current user
        await _workspaceUserRepository.UpdateRoleAsync(request.NewAdminUserId, workspaceId, WorkspaceRole.WorkspaceAdmin);
        await _workspaceUserRepository.UpdateRoleAsync(userId, workspaceId, WorkspaceRole.Normal);

        _logger.LogInformation("User {UserId} transferred admin role to user {NewAdminUserId} in workspace {WorkspaceId}",
            userId, request.NewAdminUserId, workspaceId);

        // Update the current user's token with their new role
        var user = await _userRepository.GetByIdAsync(userId);
        if (user != null && user.ActiveWorkspaceId == workspaceId)
        {
            var appToken = _tokenService.GenerateAppToken(user, WorkspaceRole.Normal);
            Response.SetAuthCookie(appToken, _settings);
        }

        return Ok(new TransferAdminResponse { Success = true });
    }
}
