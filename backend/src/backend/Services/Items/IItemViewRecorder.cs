namespace OneBigHead.Server.Services.Items;

/// <summary>Best-effort view statistics; recording a view never prevents reading an item.</summary>
public interface IItemViewRecorder
{
    Task RecordAsync(int workspaceId, int id);
}
