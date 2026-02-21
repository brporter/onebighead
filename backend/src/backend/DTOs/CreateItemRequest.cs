using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class CreateItemRequest : ItemRequestBase
{
    public Item ToItem(int workspaceId)
    {
        var item = new Item { WorkspaceId = workspaceId };
        PopulateItem(item);
        return item;
    }
}