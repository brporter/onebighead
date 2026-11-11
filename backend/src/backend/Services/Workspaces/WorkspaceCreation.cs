using System.ComponentModel.DataAnnotations;
using System.Data;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Workspaces;

/// <summary>Creates an empty workspace and its first administrator atomically.</summary>
public sealed class WorkspaceCreation(IDbContextFactory<AppDbContext> contextFactory, TimeProvider time,
    ILogger<WorkspaceCreation> logger) : IWorkspaceCreation
{
    public async Task<WorkspaceCreationResult> CreateAsync(int userId, CreateWorkspaceRequest request)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        try
        {
            if (!await context.Users.AnyAsync(u => u.Id == userId && !u.IsDeleted))
                return new(WorkspaceCreationStatus.Forbidden);
            if (!Validator.TryValidateObject(request, new ValidationContext(request), null, validateAllProperties: true))
                return new(WorkspaceCreationStatus.Invalid, Error: "Enter a workspace name of 1–200 characters");

            var now = time.GetUtcNow().UtcDateTime;
            var workspace = new Workspace { Name = request.Name.Trim(), CreatedAt = now };
            workspace.WorkspaceUsers.Add(new WorkspaceUser { UserId = userId, WorkspaceRole = WorkspaceRole.WorkspaceAdmin, CreatedAt = now });
            context.Workspaces.Add(workspace);
            await context.SaveChangesAsync();
            await transaction.CommitAsync();
            logger.LogInformation("User {UserId} created workspace {WorkspaceId}", userId, workspace.Id);
            return new(WorkspaceCreationStatus.Created, new CreateWorkspaceResponse
            {
                WorkspaceId = workspace.Id, WorkspaceName = workspace.Name,
                WorkspaceRole = WorkspaceRole.WorkspaceAdmin, HasCompletedWelcome = false
            });
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception))
        {
            return new(WorkspaceCreationStatus.Conflict, Error: "Your account changed. Reload your workspaces before creating one");
        }
    }
}
