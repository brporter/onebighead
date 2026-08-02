namespace OneBigHead.Server.Authentication;

/// <summary>
/// Maps <see cref="AuthErrorType"/> values to user-facing messages shown on the sign-in page.
/// </summary>
public static class AuthErrorMessages
{
    public static string? GetMessage(AuthErrorType errorType)
    {
        return errorType switch
        {
            AuthErrorType.SessionRevoked => "Your session is no longer valid because your access was changed. Please sign in again.",
            _ => null
        };
    }
}
