namespace OneBigHead.Server.Authentication;

/// <summary>
/// Identifies the cause of a 401 response so the sign-in page can display
/// an appropriate message. Values are passed as the "errorType" query string
/// parameter on the sign-in redirect and mapped back to display strings by
/// <see cref="AuthErrorMessages"/>.
/// </summary>
public enum AuthErrorType
{
    None = 0,

    /// <summary>
    /// The token was revoked server-side (e.g., the user was removed from a
    /// workspace or their role changed) and a fresh sign-in is required.
    /// </summary>
    SessionRevoked = 1
}
