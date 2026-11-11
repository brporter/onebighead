using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Collections;

internal static class CollectionWriteAccess
{
    public static IQueryable<Collection> ForMember(AppDbContext context, int userId, int workspaceId) =>
        context.Collections.Where(collection => collection.WorkspaceId == workspaceId && !collection.Workspace!.IsDeleted &&
            context.WorkspaceUsers.Any(member => member.UserId == userId && member.WorkspaceId == workspaceId && !member.User.IsDeleted));
}
