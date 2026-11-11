using System.Data;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Accounts;

public sealed class AccountDeletion(
    IDbContextFactory<AppDbContext> contextFactory,
    TimeProvider time,
    ILogger<AccountDeletion> logger) : IAccountDeletion
{
    public async Task<AccountDeletionResult> DeleteAsync(int userId, DeleteUserRequest request)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        try
        {
            var user = await AccountDeletionSnapshot.LoadAsync(context, userId);
            if (user is null) return new(AccountDeletionStatus.Invalid, "User not found");
            var error = AccountDeletionPolicy.Validate(AccountDeletionPolicy.Describe(user), request);
            if (error is not null) return new(AccountDeletionStatus.Invalid, error);

            var deletedAt = time.GetUtcNow().UtcDateTime;
            foreach (var action in request.WorkspaceActions.OrderBy(a => a.WorkspaceId))
            {
                var workspace = user.WorkspaceMemberships.Single(m => m.WorkspaceId == action.WorkspaceId).Workspace;
                if (action.Action == WorkspaceActionType.Delete)
                {
                    workspace.IsDeleted = true;
                    workspace.DeletedAt = deletedAt;
                    workspace.DeletedByUserId = userId;
                }
                else
                    workspace.WorkspaceUsers.Single(m => m.UserId == action.TransferToUserId).WorkspaceRole = WorkspaceRole.WorkspaceAdmin;
            }

            // Cascades remove every membership and revocation row; shared content
            // and audit history survive. No independently committing service calls.
            context.Users.Remove(user);
            await context.SaveChangesAsync();
            await transaction.CommitAsync();
            logger.LogInformation("Deleted user account {UserId} and resolved its workspace memberships", userId);
            return new(AccountDeletionStatus.Deleted);
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception))
        {
            return new(AccountDeletionStatus.Conflict, "Workspace membership changed. Reload account deletion information and review your choices");
        }
    }
}
