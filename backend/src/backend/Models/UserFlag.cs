namespace OneBigHead.Server.Models;

/// <summary>
/// Represents a user's relationship with an item - whether they have it,
/// want it, or are willing to trade/sell it.
/// </summary>
public enum UserFlag
{
    /// <summary>User has this item in their collection.</summary>
    Have = 1,

    /// <summary>User wants to acquire this item.</summary>
    Want = 2,

    /// <summary>User is willing to trade or sell this item.</summary>
    TradeOrSell = 3
}
