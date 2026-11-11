using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Items;

public sealed class ItemViewRecorder(
    IItemRepository items,
    IWorkspaceStatisticsRepository workspaces,
    ICollectionStatisticsRepository collections,
    TimeProvider clock) : IItemViewRecorder
{
    public async Task RecordAsync(int workspaceId, int id)
    {
        try
        {
            var item = await items.GetByIdAsync(id, workspaceId);
            if (item is null) return;
            await workspaces.IncrementAsync(workspaceId, StatisticType.DailyItemView, 1,
                DateOnly.FromDateTime(clock.GetUtcNow().UtcDateTime));
            await collections.IncrementItemViewAsync(item.CollectionId, id);
        }
        catch
        {
            // View counts are non-critical and must not fail the user's request.
        }
    }
}
