using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Collections;

public enum CollectionWriteStatus { Success, NotFound, Forbidden, Invalid, Conflict }

public sealed record CollectionWriteResult(CollectionWriteStatus Status, Collection? Collection = null, string? Error = null)
{
    public static CollectionWriteResult ConcurrentChange() => new(CollectionWriteStatus.Conflict,
        Error: "Collection data changed. Reload the collection and review your changes.");
}
