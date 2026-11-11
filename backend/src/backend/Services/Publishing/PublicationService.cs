using System.Data;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Publishing;

public sealed class PublicationService(IDbContextFactory<AppDbContext> contextFactory, IVisibilityService visibility) : IPublicationService
{
    public async Task<PublicationResult<PreflightResponse>> PreflightAsync(int workspaceId, PreflightRequest request, CancellationToken cancellationToken = default)
    {
        await using var context = await contextFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.RepeatableRead, cancellationToken);
        var loaded = await PublicationSnapshot.LoadAsync(context, workspaceId, request.Action, request.Entities, cancellationToken);
        if (loaded.Error is { } loadError) return PublicationResult<PreflightResponse>.Failure(loadError);
        var planned = PublicationPlan.Build(loaded.Value!, request.Action, visibility);
        return planned.Error is { } planError ? PublicationResult<PreflightResponse>.Failure(planError)
            : PublicationResult<PreflightResponse>.Success(new() { Ready = planned.Value!.Requirements.Count == 0, Requirements = planned.Value.Requirements });
    }

    public async Task<PublicationResult<ExecuteResponse>> ExecuteAsync(int workspaceId, ExecuteRequest request, CancellationToken cancellationToken = default)
    {
        await using var context = await contextFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        try
        {
            var loaded = await PublicationSnapshot.LoadAsync(context, workspaceId, request.Action, request.Entities, cancellationToken);
            if (loaded.Error is { } loadError) return PublicationResult<ExecuteResponse>.Failure(loadError);
            var snapshot = loaded.Value!;
            var planned = PublicationPlan.Build(snapshot, request.Action, visibility);
            if (planned.Error is { } planError) return PublicationResult<ExecuteResponse>.Failure(planError);
            var plan = planned.Value!;
            if (plan.Requirements.Any(requirement => !PublicationConsent.IsResolved(requirement, request.Resolutions)))
                return NeedsReview(plan, "Review and resolve every visibility requirement, including a valid gallery URL.");

            string? slugSet = null;
            if (plan.Requirements.OfType<WorkspaceSlugRequiredRequirement>().Any())
            {
                slugSet = request.Resolutions.OfType<WorkspaceSlugResolution>().Single().Slug;
                if (await context.Workspaces.AnyAsync(workspace => workspace.Id != workspaceId && workspace.Slug == slugSet, cancellationToken))
                    return NeedsReview(plan, "This gallery URL is already taken. Choose another URL.");
                snapshot.Workspace.Slug = slugSet;
            }
            var desired = request.Action == PublishAction.Publish ? Visibility.Public : Visibility.Private;
            foreach (var entity in plan.Changed.Concat(plan.Promoted)) snapshot.Apply(entity, desired);
            await context.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return PublicationResult<ExecuteResponse>.Success(new() { Success = true, Changed = plan.Changed, Promoted = plan.Promoted, WorkspaceSlugSet = slugSet });
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception))
        {
            return PublicationResult<ExecuteResponse>.Failure(new(PublicationFailure.Conflict, "The collection changed while saving. Check visibility again before continuing."));
        }
        catch (DbUpdateException exception) when (exception.GetBaseException() is PostgresException
            { SqlState: PostgresErrorCodes.UniqueViolation, ConstraintName: "IX_Workspaces_Slug" })
        {
            return PublicationResult<ExecuteResponse>.Failure(new(PublicationFailure.Conflict, "This gallery URL was just taken. Check visibility again and choose another URL."));
        }
    }

    private static PublicationResult<ExecuteResponse> NeedsReview(PublicationPlan plan, string message) =>
        PublicationResult<ExecuteResponse>.Success(new() { Success = false, Error = message, Requirements = plan.Requirements });
}
