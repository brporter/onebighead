using System.ComponentModel.DataAnnotations;
using System.Data;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Collections;
using OneBigHead.Server.Services.Memberships;
using OneBigHead.Server.Utilities;

namespace OneBigHead.Server.Services.Workspaces;

/// <summary>Creates and activates a workspace, initial collection and membership atomically.</summary>
public sealed class WorkspaceSetup(IDbContextFactory<AppDbContext> contextFactory,
    IWorkspaceStatisticsWriter statistics, TimeProvider time, ILogger<WorkspaceSetup> logger) : IWorkspaceSetup
{
    public async Task<WorkspaceSetupResult> CreateAsync(int userId, SetupWorkspaceRequest request)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        try
        {
            var user = await MembershipSnapshot.LoadActiveUserAsync(context, userId);
            if (user is null) return new(WorkspaceSetupStatus.Forbidden);
            if (!Validator.TryValidateObject(request, new ValidationContext(request), null, validateAllProperties: true))
                return new(WorkspaceSetupStatus.Invalid, Error: "Enter a workspace name of 1–200 characters, a collection name of at most 200 characters, and a description of at most 1,000 characters");
            var requestId = request.RequestId!.Value;
            if (requestId == Guid.Empty)
                return new(WorkspaceSetupStatus.Invalid, Error: "A nonempty setup request ID is required");
            var draft = WorkspaceSetupDraft.FromRequest(request);
            var requestHash = draft.Fingerprint();
            var replay = await WorkspaceSetupReplay.ReadAsync(context, user, requestId, requestHash);
            if (replay is not null)
            {
                await transaction.CommitAsync();
                return replay;
            }

            // Resolve the theme in the same snapshot as its referenced templates.
            // Preserve the API's fallback to General, then the first ordered theme.
            var theme = await context.CollectionThemes.AsNoTracking().Include(t => t.ThemeTemplates).Include(t => t.ThemeCategories)
                .AsSingleQuery().OrderBy(t => t.Id == request.ThemeId ? 0 : t.Name == Constants.ThemeNames.General ? 1 : 2)
                .ThenBy(t => t.SortOrder).ThenBy(t => t.Id).FirstOrDefaultAsync();
            var now = time.GetUtcNow().UtcDateTime;
            var workspace = new Workspace { Name = draft.WorkspaceName, HasCompletedWelcome = true, CreatedAt = now };
            workspace.WorkspaceUsers.Add(new WorkspaceUser { User = user, WorkspaceRole = WorkspaceRole.WorkspaceAdmin, CreatedAt = now });
            user.ActiveWorkspace = workspace;
            var collection = new Collection
            {
                Workspace = workspace, CreatedAt = now,
                Name = draft.CollectionName, Description = draft.Description
            };
            await CollectionSetupWrite.SaveAsync(context, collection, theme, statistics);
            context.WorkspaceSetupReceipts.Add(new WorkspaceSetupReceipt
            {
                UserId = userId, RequestId = requestId, RequestHash = requestHash,
                WorkspaceId = workspace.Id, CollectionId = collection.Id, CreatedAt = now
            });
            await context.SaveChangesAsync();
            var session = CurrentUserSession.FromUser(user);
            await transaction.CommitAsync();
            logger.LogInformation("User {UserId} created workspace {WorkspaceId} with collection {CollectionId}", userId, workspace.Id, collection.Id);
            return new(WorkspaceSetupStatus.Created, new SetupWorkspaceResponse
            {
                WorkspaceId = workspace.Id, WorkspaceName = workspace.Name, WorkspaceRole = session.Response.WorkspaceRole,
                CollectionId = collection.Id, CollectionName = collection.Name
            }, session);
        }
        catch (InvalidCollectionThemeException exception)
        {
            return new(WorkspaceSetupStatus.Invalid, Error: exception.Message);
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception) ||
            exception.GetBaseException() is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation, ConstraintName: "PK_WorkspaceSetupReceipts" })
        {
            return new(WorkspaceSetupStatus.Conflict, Error: "Your account or setup data changed. Refresh your session and review setup before continuing");
        }
    }
}
