using System.ComponentModel.DataAnnotations;
using System.Data;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Invitations;

namespace OneBigHead.Server.Services.Memberships;

public sealed class TeamInvitations(
    IDbContextFactory<AppDbContext> contextFactory,
    TimeProvider time,
    ILogger<TeamInvitations> logger) : ITeamInvitations
{
    public async Task<TeamInvitationResult> InviteAsync(int actorId, int workspaceId, InviteUserRequest request)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        try
        {
            if (!await TeamAdministrator.Membership(context, actorId, workspaceId).AnyAsync())
                return new(TeamInvitationStatus.Forbidden);
            if (!Validator.TryValidateObject(request, new ValidationContext(request), null, validateAllProperties: true))
                return new(TeamInvitationStatus.Invalid, Error: "Enter a valid email address");
            if (!Enum.IsDefined(request.Role))
                return new(TeamInvitationStatus.Invalid, Error: "Choose a valid workspace role");

            // An invitation is a pending grant, independent of any matching account email.
            var email = request.Email.Trim().ToLowerInvariant();
            var invitation = await context.WorkspaceInvitations.SingleOrDefaultAsync(candidate =>
                candidate.WorkspaceId == workspaceId && candidate.Email == email && candidate.AcceptedAt == null);
            var now = time.GetUtcNow().UtcDateTime;
            if (invitation is null)
            {
                invitation = new WorkspaceInvitation { WorkspaceId = workspaceId, Email = email, CreatedAt = now };
                context.WorkspaceInvitations.Add(invitation);
            }
            var token = InvitationTokens.Create();
            invitation.Role = request.Role;
            invitation.TokenHash = InvitationTokens.Hash(token);
            invitation.ExpiresAt = now.AddDays(7);
            await context.SaveChangesAsync();
            await transaction.CommitAsync();
            logger.LogInformation("User {ActorId} created invitation {InvitationId} for workspace {WorkspaceId}", actorId, invitation.Id, workspaceId);
            return new(TeamInvitationStatus.Created, new(WorkspaceInvitationResponse.FromInvitation(invitation), token));
        }
        catch (Exception exception) when (DatabaseConcurrency.IsConflict(exception) ||
            exception.GetBaseException() is PostgresException
                { SqlState: PostgresErrorCodes.UniqueViolation, ConstraintName: "IX_WorkspaceInvitations_WorkspaceId_Email" })
        {
            return new(TeamInvitationStatus.Conflict, Error: "Workspace membership changed. Reload the team and review the invitation");
        }
    }
}
