using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Authentication;

[Trait("Category", "Unit")]
public class ExternalUserServiceTests
{
    [Theory]
    [InlineData(true, true, true)]
    [InlineData(true, false, false)]
    [InlineData(false, true, true)]
    [InlineData(false, false, false)]
    public async Task ExistingAccount_RestoresIfDeletedAndKeepsMembershipRole(bool matchingProvider, bool deleted, bool hasMembership)
    {
        var users = new Mock<IUserRepository>();
        var memberships = new Mock<IWorkspaceUserRepository>();
        var user = new User { Id = 1, ActiveWorkspaceId = 2, Email = "user@example.com", ProviderSubjectId = "subject", IsDeleted = deleted, DeletedAt = deleted ? DateTime.UtcNow : null };
        if (matchingProvider) users.Setup(r => r.GetByProviderIdAsync(IdentityProvider.Google, "subject")).ReturnsAsync(user);
        else users.Setup(r => r.GetByEmailAsync(user.Email)).ReturnsAsync(user);
        if (hasMembership) memberships.Setup(r => r.GetMembershipAsync(1, 2)).ReturnsAsync(new WorkspaceUser { WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
        var result = await new ExternalUserService(users.Object, memberships.Object, NullLogger<ExternalUserService>.Instance)
            .GetOrCreateAsync(IdentityProvider.Google, Identity());
        Assert.Same(user, result.user);
        Assert.False(user.IsDeleted);
        Assert.Null(user.DeletedAt);
        Assert.Equal(hasMembership ? WorkspaceRole.WorkspaceAdmin : WorkspaceRole.Normal, result.workspaceRole);
        users.Verify(r => r.UpdateAsync(user), deleted ? Times.Once : Times.Never);
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public async Task PendingAccount_LinksIdentity(bool deleted, bool linkSucceeds)
    {
        var users = new Mock<IUserRepository>();
        var memberships = new Mock<IWorkspaceUserRepository>();
        var pending = new User { Id = 1, ActiveWorkspaceId = 2, Email = "user@example.com", IsDeleted = deleted };
        users.Setup(r => r.GetByEmailAsync(pending.Email)).ReturnsAsync(pending);
        users.Setup(r => r.LinkUserAsync(1, IdentityProvider.Google, "subject")).ReturnsAsync(linkSucceeds ? pending : null);
        var result = await new ExternalUserService(users.Object, memberships.Object, NullLogger<ExternalUserService>.Instance)
            .GetOrCreateAsync(IdentityProvider.Google, Identity());
        Assert.Equal(linkSucceeds ? pending : null, result.user);
        Assert.Equal(WorkspaceRole.Normal, result.workspaceRole);
        users.Verify(r => r.UpdateAsync(pending), deleted ? Times.Once : Times.Never);
    }

    [Fact]
    public async Task NewAccount_ProvisionsAnAdminWorkspace()
    {
        var users = new Mock<IUserRepository>();
        var user = new User { Id = 1 };
        users.Setup(r => r.CreateWithNewWorkspaceAsync("user@example.com", IdentityProvider.Google, "subject")).ReturnsAsync(user);
        var result = await new ExternalUserService(users.Object, Mock.Of<IWorkspaceUserRepository>(), NullLogger<ExternalUserService>.Instance)
            .GetOrCreateAsync(IdentityProvider.Google, Identity());
        Assert.Same(user, result.user);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, result.workspaceRole);
    }

    private static OidcValidationResult Identity() => new() { IsValid = true, Email = "user@example.com", Subject = "subject" };
}
