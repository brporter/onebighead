namespace OneBigHead.Server.Authentication;

public interface ITokenRevocationService
{
    /// <summary>Invalidates every existing account snapshot, including cookies signed later from stale data.</summary>
    Task RevokeAsync(int userId);
}
