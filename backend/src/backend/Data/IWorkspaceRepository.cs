using OneBigHead.Server.Models;
using OneBigHead.Server.Telemetry;

namespace OneBigHead.Server.Data;

[GenerateTracingProxy]
public interface IWorkspaceRepository
{
    Task<Workspace?> GetByIdAsync(int id);
    Task UpdateAsync(Workspace workspace);
    Task CreateAsync(Workspace workspace);

    /// <summary>
    /// Gets statistics for a workspace (collection, item, category, and image counts).
    /// Used for displaying workspace stats before deletion or restoration.
    /// </summary>
    Task<WorkspaceStats> GetStatsAsync(int workspaceId);

    /// <summary>
    /// Gets a workspace by its public slug. Only returns workspaces with public access enabled.
    /// </summary>
    Task<Workspace?> GetBySlugAsync(string slug);
}

/// <summary>
/// Statistics for a workspace.
/// </summary>
public class WorkspaceStats
{
    public int CollectionCount { get; set; }
    public int ItemCount { get; set; }
    public int CategoryCount { get; set; }
    public int ImageCount { get; set; }
}
