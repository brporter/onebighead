using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Authentication;

public sealed record CurrentUserSession(User User, CurrentUserResponse Response)
{
    /// <summary>Projects a loaded snapshot and omits stale/deleted active membership from its cookie identity.</summary>
    public static CurrentUserSession FromUser(User user)
    {
        var response = CurrentUserResponse.FromUser(user);
        user.ActiveWorkspaceId = response.WorkspaceId;
        return new(user, response);
    }
}

/// <summary>Reads one authoritative account and membership snapshot for session refresh.</summary>
public interface ICurrentUserSessionReader
{
    Task<CurrentUserSession?> ReadAsync(int userId);
}
