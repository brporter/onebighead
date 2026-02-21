using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class UpdateItemRequest : ItemRequestBase
{
    public Item ToItem(int id, int workspaceId)
    {
        var item = new Item { Id = id, WorkspaceId = workspaceId };
        PopulateItem(item);
        return item;
    }
}