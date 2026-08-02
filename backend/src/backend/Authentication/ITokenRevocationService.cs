namespace OneBigHead.Server.Authentication;

public interface ITokenRevocationService
{
    /// <summary>
    /// Invalidates all tokens issued to the user before now. Call whenever a user's
    /// authorization changes (workspace removal, role change) so stale claims cannot
    /// be replayed; the user must sign in again to receive a token with current claims.
    /// </summary>
    Task RevokeAsync(int userId);

    /// <summary>
    /// Returns true when a token issued at <paramref name="issuedAtUtc"/> for the user
    /// has been revoked. Results are cached briefly, so revocation takes effect within
    /// the cache TTL on instances other than the one that performed the revocation.
    /// </summary>
    Task<bool> IsTokenRevokedAsync(int userId, DateTime issuedAtUtc);
}
