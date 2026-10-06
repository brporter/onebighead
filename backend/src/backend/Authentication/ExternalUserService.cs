using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Authentication;

public interface IExternalUserService
{
    Task<(User? user, WorkspaceRole workspaceRole)> GetOrCreateAsync(IdentityProvider provider, OidcValidationResult identity);
}

public class ExternalUserService(IUserRepository users, IWorkspaceUserRepository memberships,
    ILogger<ExternalUserService> logger) : IExternalUserService
{
    public async Task<(User? user, WorkspaceRole workspaceRole)> GetOrCreateAsync(IdentityProvider provider, OidcValidationResult validationResult)
    {
        // 1. Check for existing linked user by provider ID
        var user = await users.GetByProviderIdAsync(provider, validationResult.Subject!);
        if (user != null)
        {
            // Restore soft-deleted user
            if (user.IsDeleted)
            {
                user.IsDeleted = false;
                user.DeletedAt = null;
                await users.UpdateAsync(user);
                logger.LogInformation("Restored soft-deleted user {UserId} ({Email}) on sign-in",
                    user.Id, user.Email);
            }

            var membership = await memberships.GetMembershipAsync(user.Id, user.ActiveWorkspaceId);
            return (user, membership?.WorkspaceRole ?? WorkspaceRole.Normal);
        }

        // 2. Check for pending user by email (email linking)
        var pendingUser = await users.GetByEmailAsync(validationResult.Email!);
        if (pendingUser != null && !pendingUser.IsLinked)
        {
            // Restore if soft-deleted
            if (pendingUser.IsDeleted)
            {
                pendingUser.IsDeleted = false;
                pendingUser.DeletedAt = null;
                await users.UpdateAsync(pendingUser);
                logger.LogInformation("Restored soft-deleted pending user {UserId} on link", pendingUser.Id);
            }

            // Link pending user to this OAuth identity
            logger.LogInformation("Linking pending user {Email} to {Provider}", validationResult.Email, provider);
            var linkedUser = await users.LinkUserAsync(
                pendingUser.Id, provider, validationResult.Subject!);
            if (linkedUser != null)
            {
                var membership = await memberships.GetMembershipAsync(linkedUser.Id, linkedUser.ActiveWorkspaceId);
                return (linkedUser, membership?.WorkspaceRole ?? WorkspaceRole.Normal);
            }
            return (null, WorkspaceRole.Normal);
        }

        if (pendingUser != null)
        {
            // User exists with same email but different provider (already linked)
            // Restore if soft-deleted
            if (pendingUser.IsDeleted)
            {
                pendingUser.IsDeleted = false;
                pendingUser.DeletedAt = null;
                await users.UpdateAsync(pendingUser);
                logger.LogInformation("Restored soft-deleted user {UserId} ({Email}) on sign-in with different provider",
                    pendingUser.Id, pendingUser.Email);
            }
            logger.LogInformation("User {Email} authenticated with different provider", validationResult.Email);
            var membership = await memberships.GetMembershipAsync(pendingUser.Id, pendingUser.ActiveWorkspaceId);
            return (pendingUser, membership?.WorkspaceRole ?? WorkspaceRole.Normal);
        }

        // 3. Auto-provision new user with new workspace (first-time signup)
        logger.LogInformation("Auto-provisioning new user with email {Email}", validationResult.Email);
        var newUser = await users.CreateWithNewWorkspaceAsync(
            validationResult.Email!,
            provider,
            validationResult.Subject!);
        // New users are WorkspaceAdmin of their own workspace
        return (newUser, WorkspaceRole.WorkspaceAdmin);
    }

}
