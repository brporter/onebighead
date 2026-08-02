namespace OneBigHead.Server.Data;

public interface ITokenRevocationRepository
{
    /// <summary>
    /// Returns the revocation cutoff for a user, or null if the user has no revocation entry.
    /// Tokens issued before the returned timestamp are invalid.
    /// </summary>
    Task<DateTime?> GetRevokedAtUtcAsync(int userId);

    /// <summary>
    /// Creates or advances the revocation cutoff for a user.
    /// </summary>
    Task UpsertAsync(int userId, DateTime revokedAtUtc);
}
