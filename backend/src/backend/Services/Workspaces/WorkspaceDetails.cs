using System.ComponentModel.DataAnnotations;
using System.Data;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Workspaces;

/// <summary>Authorizes and updates workspace metadata in one database snapshot.</summary>
public sealed class WorkspaceDetails(IDbContextFactory<AppDbContext> contextFactory,
    ILogger<WorkspaceDetails> logger) : IWorkspaceDetails
{
    public async Task<WorkspaceDetailsResult> UpdateAsync(int userId, int workspaceId, UpdateWorkspaceRequest request)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        try
        {
            var membership = await context.WorkspaceUsers.Include(m => m.Workspace)
                .SingleOrDefaultAsync(m => m.UserId == userId && m.WorkspaceId == workspaceId && !m.User.IsDeleted && !m.Workspace.IsDeleted);
            if (membership is null) return new(WorkspaceDetailsStatus.NotFound, Error: "Workspace not found");
            if (membership.WorkspaceRole != WorkspaceRole.WorkspaceAdmin) return new(WorkspaceDetailsStatus.Forbidden);
            if (!Validator.TryValidateObject(request, new ValidationContext(request), null, validateAllProperties: true))
                return new(WorkspaceDetailsStatus.Invalid, Error: "Enter a name of 1–200 characters and a valid gallery slug");

            // Deleted workspaces retain their URLs until permanent deletion,
            // matching the unique index and preserving their recovery rights.
            if (request.Slug is not null && await context.Workspaces.AnyAsync(w => w.Slug == request.Slug && w.Id != workspaceId))
                return new(WorkspaceDetailsStatus.Conflict, Error: "This slug is already taken");

            var workspace = membership.Workspace;
            workspace.Name = request.Name.Trim();
            workspace.Slug = request.Slug;
            if (context.ChangeTracker.HasChanges()) await context.SaveChangesAsync();
            await transaction.CommitAsync();
            logger.LogInformation("User {UserId} updated workspace {WorkspaceId} details", userId, workspaceId);
            return new(WorkspaceDetailsStatus.Updated, new UpdateWorkspaceResponse
            {
                WorkspaceId = workspace.Id, WorkspaceName = workspace.Name, Slug = workspace.Slug,
                PublicUrl = workspace.Slug is null ? null : $"/public/{workspace.Slug}"
            });
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception) ||
            exception.GetBaseException() is PostgresException
                { SqlState: PostgresErrorCodes.UniqueViolation, ConstraintName: "IX_Workspaces_Slug" })
        {
            return new(WorkspaceDetailsStatus.Conflict, Error: "Workspace details changed. Refresh your workspaces and review the name and gallery URL");
        }
    }
}
