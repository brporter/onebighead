using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Items;

public enum ItemWriteStatus { Success, NotFound, Invalid, Conflict }

public sealed record ItemWriteResult(ItemWriteStatus Status, Item? Item = null, string? Error = null);
