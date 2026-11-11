namespace OneBigHead.Server.Services.Accounts;

public interface IAccountTerms
{
    /// <summary>Records consent for a current, non-deleted account; returns null if it is unavailable.</summary>
    Task<DateTime?> AcceptAsync(int userId, CancellationToken cancellationToken);
}
