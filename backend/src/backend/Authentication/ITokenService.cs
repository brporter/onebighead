using System.Security.Claims;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Authentication;

public interface ITokenService
{
    string GenerateAppToken(User user, WorkspaceRole workspaceRole);
    ClaimsPrincipal? ValidateAppToken(string token);
}