using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;

namespace OneBigHead.Server.Services.Workspaces;

/// <summary>Shared active-workspace policy for soft and permanent deletion; the caller owns the transaction.</summary>
internal static class WorkspaceSessionAssignments
{
    public static async Task ReassignAsync(AppDbContext context, int workspaceId)
    {
        var users = await context.Users.Where(u => u.ActiveWorkspaceId == workspaceId).ToListAsync();
        var userIds = users.Select(u => u.Id).ToArray();
        var alternatives = await context.WorkspaceUsers
            .Where(m => userIds.Contains(m.UserId) && m.WorkspaceId != workspaceId && !m.Workspace.IsDeleted)
            .OrderBy(m => m.WorkspaceId).Select(m => new { m.UserId, m.WorkspaceId }).ToListAsync();
        var replacements = alternatives.GroupBy(m => m.UserId).ToDictionary(g => g.Key, g => (int?)g.First().WorkspaceId);
        foreach (var user in users) user.ActiveWorkspaceId = replacements.GetValueOrDefault(user.Id);
    }
}
