using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Workspaces;

/// <summary>Resolves a committed creation without restoring old membership or active-workspace state.</summary>
internal static class WorkspaceSetupReplay
{
    public static async Task<WorkspaceSetupResult?> ReadAsync(AppDbContext context, User user, Guid requestId, string hash)
    {
        var receipt = await context.WorkspaceSetupReceipts.AsNoTracking()
            .SingleOrDefaultAsync(receipt => receipt.UserId == user.Id && receipt.RequestId == requestId);
        if (receipt is null) return null;
        if (receipt.RequestHash != hash)
            return new(WorkspaceSetupStatus.Conflict, Error: "This setup request was already used with different details. Recover the original setup before creating another workspace");
        var membership = user.WorkspaceMemberships.SingleOrDefault(m => m.WorkspaceId == receipt.WorkspaceId && !m.Workspace.IsDeleted);
        if (membership is null)
            return new(WorkspaceSetupStatus.Unavailable, Error: "This workspace was already created, but it is no longer available to your account. You can close setup or start a new workspace");
        var collection = await context.Collections.AsNoTracking()
            .Where(c => c.Id == receipt.CollectionId && c.WorkspaceId == membership.WorkspaceId)
            .Select(c => new { c.Id, c.Name }).SingleOrDefaultAsync();
        return new(WorkspaceSetupStatus.Created, new SetupWorkspaceResponse
        {
            WorkspaceId = membership.WorkspaceId, WorkspaceName = membership.Workspace.Name, WorkspaceRole = membership.WorkspaceRole,
            CollectionId = collection?.Id, CollectionName = collection?.Name
        }, CurrentUserSession.FromUser(user));
    }
}
