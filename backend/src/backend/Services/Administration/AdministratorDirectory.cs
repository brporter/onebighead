using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;

namespace OneBigHead.Server.Services.Administration;

/** Cross-workspace read models for the administrator directory. */
public sealed class AdministratorDirectory(IDbContextFactory<AppDbContext> contextFactory) : IAdministratorDirectory
{
    public async Task<IReadOnlyList<WorkspaceSummaryResponse>> GetWorkspacesAsync()
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        var workspaces = await context.Workspaces.AsNoTracking().Select(workspace => new WorkspaceSummaryResponse
        {
            WorkspaceId = workspace.Id,
            Name = workspace.Name,
            UserCount = workspace.WorkspaceUsers.Count,
            CollectionCount = workspace.Collections.Count,
            ItemCount = context.Items.Count(item => item.WorkspaceId == workspace.Id),
            CreatedAt = workspace.CreatedAt
        }).OrderBy(workspace => workspace.Name).ThenBy(workspace => workspace.WorkspaceId).ToListAsync();

        // Images use a JSON value converter; count the materialized lists rather
        // than relying on provider-specific JSON translation in this read model.
        var ids = workspaces.Select(workspace => workspace.WorkspaceId).ToArray();
        var images = await context.Items.AsNoTracking().Where(item => ids.Contains(item.WorkspaceId))
            .Select(item => new { item.WorkspaceId, item.Images }).ToListAsync();
        var counts = images.GroupBy(item => item.WorkspaceId)
            .ToDictionary(group => group.Key, group => group.Sum(item => item.Images.Count));
        foreach (var workspace in workspaces)
            workspace.ImageCount = counts.GetValueOrDefault(workspace.WorkspaceId);
        return workspaces;
    }

    public async Task<IReadOnlyList<UserSummaryResponse>> GetUsersAsync(string? email)
    {
        await using var context = await contextFactory.CreateDbContextAsync();
        var query = context.Users.AsNoTracking().Include(user => user.ActiveWorkspace).AsQueryable();
        if (!string.IsNullOrWhiteSpace(email))
        {
            var search = email.Trim().ToLowerInvariant();
            query = query.Where(user => user.Email.ToLower().Contains(search));
        }
        var users = await query.OrderBy(user => user.Email).ThenBy(user => user.Id).ToListAsync();
        return users.Select(UserSummaryResponse.FromUser).ToList();
    }
}
