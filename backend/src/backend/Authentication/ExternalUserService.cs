using System.ComponentModel.DataAnnotations;
using System.Data;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Authentication;

/// <summary>Commits account restoration or provisioning before returning a sign-in identity.</summary>
public sealed class ExternalUserService(IDbContextFactory<AppDbContext> contexts, TimeProvider time,
    ILogger<ExternalUserService> logger) : IExternalUserService
{
    public async Task<ExternalSignInResult> GetOrCreateAsync(IdentityProvider provider, OidcValidationResult identity,
        CancellationToken cancellationToken = default)
    {
        var email = identity.Email?.Trim();
        if (!identity.IsValid || !Enum.IsDefined(provider) || provider == IdentityProvider.None ||
            string.IsNullOrWhiteSpace(identity.Subject) || identity.Subject.Length > 255 ||
            string.IsNullOrWhiteSpace(email) || email.Length > 320 || !new EmailAddressAttribute().IsValid(email))
            return ExternalSignInResult.Rejected("The identity provider did not supply a valid account identity.");

        await using var context = await contexts.CreateDbContextAsync(cancellationToken);
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        try
        {
            var user = await context.Users.Include(user => user.ActiveWorkspace)
                .SingleOrDefaultAsync(user => user.IdentityProvider == provider && user.ProviderSubjectId == identity.Subject, cancellationToken);
            if (user is null)
            {
                // Email is provider metadata, not proof of another account's identity or invitations.
                var now = time.GetUtcNow().UtcDateTime;
                var workspace = new Workspace { Name = email[(email.LastIndexOf('@') + 1)..], CreatedAt = now };
                user = new User { Email = email, IdentityProvider = provider, ProviderSubjectId = identity.Subject,
                    ActiveWorkspace = workspace, CreatedAt = now };
                context.WorkspaceUsers.Add(new WorkspaceUser
                {
                    User = user, Workspace = workspace, WorkspaceRole = WorkspaceRole.WorkspaceAdmin, CreatedAt = now
                });
            }

            // A restored account must not reactivate cookies from before deletion.
            if (user.IsDeleted) user.AuthenticationStamp = Guid.NewGuid();
            user.IsDeleted = false;
            user.DeletedAt = null;
            await context.SaveChangesAsync(cancellationToken);
            var role = user.ActiveWorkspaceId is int workspaceId
                ? await context.WorkspaceUsers.Where(member => member.UserId == user.Id && member.WorkspaceId == workspaceId)
                    .Select(member => (WorkspaceRole?)member.WorkspaceRole).SingleOrDefaultAsync(cancellationToken) ?? WorkspaceRole.Normal
                : WorkspaceRole.Normal;
            await transaction.CommitAsync(cancellationToken);
            logger.LogInformation("Authenticated external account {UserId} with provider {Provider}", user.Id, provider);
            return new(user, role);
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception) ||
            exception.GetBaseException() is PostgresException
                { SqlState: PostgresErrorCodes.UniqueViolation, ConstraintName: "IX_Users_IdentityProvider_ProviderSubjectId" })
        {
            return ExternalSignInResult.Rejected("Account sign-in changed. Please try again.");
        }
    }
}
