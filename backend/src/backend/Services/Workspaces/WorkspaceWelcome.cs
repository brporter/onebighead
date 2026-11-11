using System.ComponentModel.DataAnnotations;
using System.Data;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Collections;

namespace OneBigHead.Server.Services.Workspaces;

/// <summary>Completes welcome once, using current account and workspace authorization.</summary>
public sealed class WorkspaceWelcome(IDbContextFactory<AppDbContext> contextFactory,
    IWorkspaceStatisticsWriter statistics, TimeProvider time, ILogger<WorkspaceWelcome> logger) : IWorkspaceWelcome
{
    public async Task<WorkspaceWelcomeResult> CompleteAsync(int userId, int workspaceId, CompleteWelcomeRequest request)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        try
        {
            var membership = await context.WorkspaceUsers.Include(m => m.Workspace).Include(m => m.User)
                .SingleOrDefaultAsync(m => m.UserId == userId && m.WorkspaceId == workspaceId && !m.User.IsDeleted && !m.Workspace.IsDeleted);
            if (membership is null) return new(WorkspaceWelcomeStatus.NotFound, Error: "Workspace not found");
            if (membership.WorkspaceRole != WorkspaceRole.WorkspaceAdmin) return new(WorkspaceWelcomeStatus.Forbidden);
            if (membership.User.ActiveWorkspaceId != workspaceId)
                return new(WorkspaceWelcomeStatus.Conflict, Error: "Your active workspace changed. Refresh your session before completing setup");
            if (!Validator.TryValidateObject(request, new ValidationContext(request), null, validateAllProperties: true))
                return new(WorkspaceWelcomeStatus.Invalid, Error: "Enter a workspace name of at most 200 characters");
            if (request.Collection is { } draft && !Validator.TryValidateObject(draft, new ValidationContext(draft), null, validateAllProperties: true))
                return new(WorkspaceWelcomeStatus.Invalid, Error: "Enter a collection name of 1–200 characters and a description of at most 1,000 characters");

            var workspace = membership.Workspace;
            var completing = !workspace.HasCompletedWelcome;
            // A repeated completion must not rename a workspace that was already
            // completed or subsequently edited in settings.
            if (completing)
            {
                var name = string.IsNullOrWhiteSpace(request.WorkspaceName) ? membership.User.Email : request.WorkspaceName.Trim();
                if (string.IsNullOrWhiteSpace(name)) name = workspace.Name;
                if (name.Length > 200)
                    return new(WorkspaceWelcomeStatus.Invalid, Error: "Enter a workspace name of at most 200 characters");
                workspace.Name = name;
                workspace.HasCompletedWelcome = true;
                if (request.Collection is { } initial)
                {
                    var theme = await context.CollectionThemes.AsNoTracking().Include(t => t.ThemeTemplates).Include(t => t.ThemeCategories)
                        .AsSingleQuery().SingleOrDefaultAsync(t => t.Id == initial.ThemeId);
                    if (theme is null) return new(WorkspaceWelcomeStatus.Invalid, Error: "Choose an available collection theme");
                    var collection = new Collection
                    {
                        Workspace = workspace, WorkspaceId = workspaceId, Name = initial.Name.Trim(),
                        Description = initial.Description?.Trim() ?? string.Empty, HeroImageUrl = initial.HeroImageUrl,
                        CreatedAt = time.GetUtcNow().UtcDateTime
                    };
                    await CollectionSetupWrite.SaveAsync(context, collection, theme, statistics);
                    workspace.WelcomeCollectionId = collection.Id;
                }
                await context.SaveChangesAsync();
            }

            var initialCollection = await context.Collections.AsNoTracking()
                .Where(c => c.Id == workspace.WelcomeCollectionId && c.WorkspaceId == workspaceId)
                .Select(c => new { c.Id, c.Name }).SingleOrDefaultAsync();
            await transaction.CommitAsync();
            if (completing) logger.LogInformation("User {UserId} completed welcome for workspace {WorkspaceId}", userId, workspaceId);
            return new(WorkspaceWelcomeStatus.Completed, new CompleteWelcomeResponse
            {
                WorkspaceId = workspace.Id, WorkspaceName = workspace.Name, HasCompletedWelcome = workspace.HasCompletedWelcome,
                CollectionId = initialCollection?.Id, CollectionName = initialCollection?.Name
            });
        }
        catch (InvalidCollectionThemeException exception)
        {
            return new(WorkspaceWelcomeStatus.Invalid, Error: exception.Message);
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception))
        {
            return new(WorkspaceWelcomeStatus.Conflict, Error: "Workspace setup changed. Refresh your session and review setup before continuing");
        }
    }
}
