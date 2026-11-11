namespace OneBigHead.Server.Authentication;

/// <summary>Checks the account snapshot in a signed cookie against current account state.</summary>
public interface IAccountSessionValidator
{
    Task<bool> IsCurrentAsync(int userId, Guid authenticationStamp, CancellationToken cancellationToken = default);
}
