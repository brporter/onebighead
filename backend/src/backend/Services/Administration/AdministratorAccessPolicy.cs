using OneBigHead.Server.Models;

namespace OneBigHead.Server.Services.Administration;

public static class AdministratorAccessPolicy
{
    public static bool IsAllowed(User? user) => user is { IsSystemAdministrator: true, IsDeleted: false };
}
