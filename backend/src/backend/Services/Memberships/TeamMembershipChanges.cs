using System.Data;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Memberships;

/// <summary>Owns the authorization and transaction boundary shared by team membership edits.</summary>
public sealed class TeamMembershipChanges(
    IDbContextFactory<AppDbContext> contextFactory,
    TimeProvider time,
    ILogger<TeamMembershipChanges> logger) : ITeamRoleChanges, ITeamMemberRemoval
{
    public Task<TeamMembershipResult> ChangeRoleAsync(int actorId, int workspaceId, int userId, WorkspaceRole role) =>
        ChangeAsync(actorId, workspaceId, userId, "You cannot change your own role", "role", (_, membership) =>
        {
            if (!Enum.IsDefined(role)) return new(TeamMembershipStatus.Invalid, "Choose a valid workspace role");
            if (membership.User.IsDeleted) return new(TeamMembershipStatus.Invalid, "Cannot change the role of a deleted account");
            membership.WorkspaceRole = role;
            return null;
        });

    public Task<TeamMembershipResult> RemoveAsync(int actorId, int workspaceId, int userId) =>
        ChangeAsync(actorId, workspaceId, userId, "You cannot remove yourself from the team", "membership", (context, membership) =>
        {
            context.WorkspaceUsers.Remove(membership);
            var user = membership.User;
            user.WorkspaceMemberships.Remove(membership);
            var remaining = user.WorkspaceMemberships.Where(m => !m.Workspace.IsDeleted).OrderBy(m => m.WorkspaceId).ToList();
            user.ActiveWorkspaceId = remaining.FirstOrDefault(m => m.WorkspaceId == user.ActiveWorkspaceId)?.WorkspaceId
                ?? remaining.FirstOrDefault()?.WorkspaceId;
            // Workspace administrators remove access to their workspace. Account
            // deletion belongs to the account owner or system administrator.
            return null;
        });

    private async Task<TeamMembershipResult> ChangeAsync(int actorId, int workspaceId, int userId,
        string selfError, string operation, Func<AppDbContext, WorkspaceUser, TeamMembershipResult?> change)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        try
        {
            // A distinct active administrator remains after this edit. Serializable
            // reads prevent two administrators from concurrently removing/demoting
            // each other and committing an administrator-less workspace.
            var authorized = await TeamAdministrator.Membership(context, actorId, workspaceId).AnyAsync();
            if (!authorized) return new(TeamMembershipStatus.Forbidden);
            if (actorId == userId) return new(TeamMembershipStatus.Invalid, selfError);

            var membership = await context.WorkspaceUsers.Include(m => m.User)
                .ThenInclude(u => u.WorkspaceMemberships).ThenInclude(m => m.Workspace)
                .AsSingleQuery().SingleOrDefaultAsync(m => m.UserId == userId && m.WorkspaceId == workspaceId);
            if (membership is null) return new(TeamMembershipStatus.NotFound, "User not found in this workspace");
            var failure = change(context, membership);
            if (failure is not null) return failure;
            // Repeating an already-established role does not revoke a newer login.
            if (!context.ChangeTracker.HasChanges()) return new(TeamMembershipStatus.Changed);

            await context.SaveChangesAsync();
            await TokenRevocationWrite.UpsertAsync(context, userId, TokenRevocationTimestamp.From(time.GetUtcNow()));
            await transaction.CommitAsync();
            logger.LogInformation("User {ActorId} updated {Operation} for user {UserId} in workspace {WorkspaceId}",
                actorId, operation, userId, workspaceId);
            return new(TeamMembershipStatus.Changed);
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception))
        {
            return new(TeamMembershipStatus.Conflict, "Workspace membership changed. Reload the team and review your changes");
        }
    }
}
