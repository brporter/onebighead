namespace OneBigHead.Server.Models;

/// <summary>
/// Records that all tokens issued to a user before <see cref="RevokedAtUtc"/> are invalid.
/// One row per user (unique index on UserId); revoking again moves the timestamp forward.
/// Rows older than the maximum token lifetime are inert since those tokens are expired anyway.
/// </summary>
public class TokenRevocation
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public DateTime RevokedAtUtc { get; set; }
}
