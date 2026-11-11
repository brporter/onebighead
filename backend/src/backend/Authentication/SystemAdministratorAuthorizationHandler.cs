using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using OneBigHead.Server.Services.Administration;

namespace OneBigHead.Server.Authentication;

public sealed class SystemAdministratorRequirement : IAuthorizationRequirement
{
    public const string PolicyName = "SystemAdministrator";
}

public sealed class SystemAdministratorAuthorizationHandler(IAdministratorAccessService access)
    : AuthorizationHandler<SystemAdministratorRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, SystemAdministratorRequirement requirement)
    {
        if (context.User.Identity?.IsAuthenticated != true ||
            !int.TryParse(context.User.FindFirstValue(ClaimTypes.NameIdentifier), out var userId) || userId <= 0) return;

        // Token roles are snapshots. A removed privilege must not survive until
        // token expiry, and a granted privilege should be usable after refresh.
        if (await access.HasAccessAsync(userId)) context.Succeed(requirement);
    }
}
