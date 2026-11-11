using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Unit;

[Trait("Category", "Unit")]
public class UserSummaryResponseTests
{
    [Fact]
    public void Summary_PreservesAccountIdentityWhenWorkspaceNavigationIsUnavailable()
    {
        var created = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var result = UserSummaryResponse.FromUser(new User { Id = 7, ActiveWorkspaceId = 9,
            Email = "reader@example.test", IdentityProvider = IdentityProvider.Google, CreatedAt = created });
        Assert.Equal(7, result.UserId);
        Assert.Equal(9, result.WorkspaceId);
        Assert.Equal("", result.WorkspaceName);
        Assert.Equal("reader@example.test", result.Email);
        Assert.Equal("Google", result.IdentityProvider);
        Assert.False(result.IsSystemAdministrator);
        Assert.Equal(created, result.CreatedAt);
    }
}
