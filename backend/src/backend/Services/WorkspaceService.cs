using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services;

public class WorkspaceService : IWorkspaceService
{
    private readonly AppDbContext _context;
    private readonly IWorkspaceRepository _workspaceRepository;
    private readonly IWorkspaceUserRepository _workspaceUserRepository;
    private readonly IUserRepository _userRepository;
    private readonly ILogger<WorkspaceService> _logger;

    public WorkspaceService(
        AppDbContext context,
        IWorkspaceRepository workspaceRepository,
        IWorkspaceUserRepository workspaceUserRepository,
        IUserRepository userRepository,
        ILogger<WorkspaceService> logger)
    {
        _context = context;
        _workspaceRepository = workspaceRepository;
        _workspaceUserRepository = workspaceUserRepository;
        _userRepository = userRepository;
        _logger = logger;
    }

    public async Task<WorkspaceStatsResponse?> GetWorkspaceStatsAsync(int workspaceId)
    {
        var workspace = await _workspaceRepository.GetByIdAsync(workspaceId);
        if (workspace == null || workspace.IsDeleted)
        {
            return null;
        }

        var collectionCount = await _context.Collections.CountAsync(c => c.WorkspaceId == workspaceId);
        var categoryCount = await _context.Categories.CountAsync(c => c.WorkspaceId == workspaceId);
        var itemCount = await _context.Items.CountAsync(i => i.WorkspaceId == workspaceId);
        var imageCount = await _context.StoredImages.CountAsync(i => i.WorkspaceId == workspaceId);
        var userCount = await _workspaceUserRepository.CountMembersInWorkspaceAsync(workspaceId);
        var adminCount = await _workspaceUserRepository.CountAdminsInWorkspaceAsync(workspaceId);

        return new WorkspaceStatsResponse
        {
            WorkspaceId = workspaceId,
            WorkspaceName = workspace.Name,
            CollectionCount = collectionCount,
            CategoryCount = categoryCount,
            ItemCount = itemCount,
            ImageCount = imageCount,
            UserCount = userCount,
            AdminCount = adminCount
        };
    }

    public async Task<WorkspaceDeletionResponse> SoftDeleteWorkspaceAsync(int workspaceId, int deletedByUserId)
    {
        var workspace = await _workspaceRepository.GetByIdAsync(workspaceId);
        if (workspace == null || workspace.IsDeleted)
        {
            return new WorkspaceDeletionResponse { Success = false };
        }

        // Soft delete the workspace
        workspace.IsDeleted = true;
        workspace.DeletedAt = DateTime.UtcNow;
        workspace.DeletedByUserId = deletedByUserId;

        await _workspaceRepository.UpdateAsync(workspace);

        _logger.LogInformation("Workspace {WorkspaceId} ({WorkspaceName}) soft-deleted by user {UserId}",
            workspaceId, workspace.Name, deletedByUserId);

        // Get all users who had this as their active workspace and switch them
        var affectedUsers = await _context.Users
            .Where(u => u.ActiveWorkspaceId == workspaceId)
            .ToListAsync();

        int? newActiveWorkspaceId = null;

        foreach (var user in affectedUsers)
        {
            // Find another workspace for this user
            var nextMembership = await _context.WorkspaceUsers
                .Include(wu => wu.Workspace)
                .Where(wu => wu.UserId == user.Id && wu.WorkspaceId != workspaceId && !wu.Workspace!.IsDeleted)
                .FirstOrDefaultAsync();

            if (nextMembership != null)
            {
                await _userRepository.UpdateActiveWorkspaceAsync(user.Id, nextMembership.WorkspaceId);

                // Track the new workspace for the requesting user
                if (user.Id == deletedByUserId)
                {
                    newActiveWorkspaceId = nextMembership.WorkspaceId;
                }

                _logger.LogInformation("User {UserId} switched from deleted workspace {OldWorkspaceId} to {NewWorkspaceId}",
                    user.Id, workspaceId, nextMembership.WorkspaceId);
            }
            else
            {
                _logger.LogWarning("User {UserId} has no other workspaces after workspace {WorkspaceId} was deleted",
                    user.Id, workspaceId);
            }
        }

        // Check if we should soft-delete the user (single-workspace admin scenario)
        bool userSoftDeleted = false;
        var deletingUser = await _userRepository.GetByIdAsync(deletedByUserId);
        if (deletingUser != null)
        {
            // Count user's workspace memberships (excluding the one being deleted)
            var otherMemberships = await _context.WorkspaceUsers
                .CountAsync(wu => wu.UserId == deletedByUserId && wu.WorkspaceId != workspaceId);

            // Check if user was WorkspaceAdmin of the deleted workspace
            var wasAdmin = await _context.WorkspaceUsers
                .AnyAsync(wu => wu.UserId == deletedByUserId &&
                                wu.WorkspaceId == workspaceId &&
                                wu.WorkspaceRole == WorkspaceRole.WorkspaceAdmin);

            if (otherMemberships == 0 && wasAdmin)
            {
                // Single-workspace admin deleting their only workspace - soft-delete user
                deletingUser.IsDeleted = true;
                deletingUser.DeletedAt = DateTime.UtcNow;
                await _userRepository.UpdateAsync(deletingUser);
                userSoftDeleted = true;

                _logger.LogInformation("User {UserId} soft-deleted after deleting their only workspace {WorkspaceId}",
                    deletedByUserId, workspaceId);
            }
        }

        return new WorkspaceDeletionResponse
        {
            Success = true,
            NewActiveWorkspaceId = newActiveWorkspaceId,
            UserSoftDeleted = userSoftDeleted
        };
    }

    public async Task<bool> IsWorkspaceDeletedAsync(int workspaceId)
    {
        var workspace = await _workspaceRepository.GetByIdAsync(workspaceId);
        return workspace?.IsDeleted ?? true;
    }

    public async Task<bool> IsUserDeletedAsync(int userId)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        return user?.IsDeleted ?? true;
    }

    public async Task<bool> HasUserAnyActiveWorkspaceAsync(int userId)
    {
        // Check if the user has any workspace memberships where the workspace is not deleted
        return await _context.WorkspaceUsers
            .Include(wu => wu.Workspace)
            .AnyAsync(wu => wu.UserId == userId && !wu.Workspace!.IsDeleted);
    }
}
