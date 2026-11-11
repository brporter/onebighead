using System.Data;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Memberships;

namespace OneBigHead.Server.Services.Workspaces;

public sealed class WorkspaceDeletionService(
    IDbContextFactory<AppDbContext> contextFactory,
    TimeProvider time,
    ILogger<WorkspaceDeletionService> logger) : IWorkspaceDeletionService
{
    public async Task<WorkspaceDeletionResult> SoftDeleteWorkspaceAsync(int workspaceId, int deletedByUserId)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        try
        {
            var user = await MembershipSnapshot.LoadActiveUserAsync(context, deletedByUserId);
            var membership = user?.WorkspaceMemberships.SingleOrDefault(m => m.WorkspaceId == workspaceId && !m.Workspace.IsDeleted);
            if (membership is null) return new(WorkspaceDeletionStatus.NotFound, Error: "Workspace not found");
            if (membership.WorkspaceRole != WorkspaceRole.WorkspaceAdmin) return new(WorkspaceDeletionStatus.Forbidden);

            var previousActiveWorkspaceId = user!.ActiveWorkspaceId;
            var workspace = membership.Workspace;
            var deletedAt = time.GetUtcNow().UtcDateTime;
            workspace.IsDeleted = true;
            workspace.DeletedAt = deletedAt;
            workspace.DeletedByUserId = deletedByUserId;
            await WorkspaceSessionAssignments.ReassignAsync(context, workspaceId);

            // Retain the established account policy, including recoverable
            // memberships: only an admin with no other membership is deleted.
            var userSoftDeleted = user.WorkspaceMemberships.Count == 1;
            if (userSoftDeleted)
            {
                user.IsDeleted = true;
                user.DeletedAt = deletedAt;
            }
            var session = userSoftDeleted ? null : CurrentUserSession.FromUser(user);
            var response = new WorkspaceDeletionResponse
            {
                Success = true, UserSoftDeleted = userSoftDeleted,
                NewActiveWorkspaceId = user.ActiveWorkspaceId != previousActiveWorkspaceId ? user.ActiveWorkspaceId : null
            };
            await context.SaveChangesAsync();
            await transaction.CommitAsync();
            logger.LogInformation("Workspace {WorkspaceId} ({WorkspaceName}) soft-deleted by user {UserId}", workspaceId, workspace.Name, deletedByUserId);
            return new(WorkspaceDeletionStatus.Deleted, response, session);
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception))
        {
            return new(WorkspaceDeletionStatus.Conflict, Error: "Workspace membership changed. Reload deletion information and review your choice");
        }
    }
}
