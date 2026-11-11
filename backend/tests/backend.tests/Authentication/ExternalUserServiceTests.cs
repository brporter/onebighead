using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Authentication;

public class ExternalUserServiceTests
{
    public static IEnumerable<object?[]> InvalidIdentities()
    {
        yield return [IdentityProvider.None, true, "owner@example.test", "subject"];
        yield return [(IdentityProvider)99, true, "owner@example.test", "subject"];
        yield return [IdentityProvider.Google, false, "owner@example.test", "subject"];
        yield return [IdentityProvider.Google, true, null, "subject"];
        yield return [IdentityProvider.Google, true, " ", "subject"];
        yield return [IdentityProvider.Google, true, "invalid", "subject"];
        yield return [IdentityProvider.Google, true, new string('a', 320) + "@example.test", "subject"];
        yield return [IdentityProvider.Google, true, "owner@example.test", null];
        yield return [IdentityProvider.Google, true, "owner@example.test", " "];
        yield return [IdentityProvider.Google, true, "owner@example.test", new string('x', 256)];
    }

    [Theory]
    [MemberData(nameof(InvalidIdentities))]
    public async Task InvalidIdentity_DoesNotReadOrWriteAccounts(IdentityProvider provider, bool valid, string? email, string? subject)
    {
        var contexts = new Mock<IDbContextFactory<AppDbContext>>(MockBehavior.Strict);
        var service = new ExternalUserService(contexts.Object, TimeProvider.System, NullLogger<ExternalUserService>.Instance);
        var result = await service.GetOrCreateAsync(provider, new OidcValidationResult { IsValid = valid, Email = email, Subject = subject });
        Assert.Null(result.User);
        Assert.Equal(WorkspaceRole.Normal, result.WorkspaceRole);
        Assert.Equal("The identity provider did not supply a valid account identity.", result.Error);
        contexts.VerifyNoOtherCalls();
    }
}
