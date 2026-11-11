using OneBigHead.Server.Models;

namespace OneBigHead.Server.Authentication;

public sealed record ExternalSignInResult(User? User, WorkspaceRole WorkspaceRole = WorkspaceRole.Normal, string? Error = null)
{
    public const string DefaultError = "Unable to sign in. Please try again.";
    public static ExternalSignInResult Rejected(string error) => new(null, Error: error);
}
