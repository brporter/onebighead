using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Models;

[Trait("Category", "Unit")]
public class UserTests
{
    [Fact]
    public void User_DefaultValues_AreCorrect()
    {
        // Act
        var user = new User();

        // Assert
        Assert.Equal(0, user.Id);
        Assert.Equal(0, user.ActiveWorkspaceId);
        Assert.Equal(string.Empty, user.Email);
        Assert.Equal(IdentityProvider.None, user.IdentityProvider);
        Assert.Null(user.ProviderSubjectId);
        Assert.Null(user.ActiveWorkspace);
        Assert.False(user.IsLinked);
    }

    [Fact]
    public void User_IsLinked_ReturnsTrueWhenProviderSubjectIdIsSet()
    {
        // Arrange
        var user = new User
        {
            ProviderSubjectId = "provider-123"
        };

        // Assert
        Assert.True(user.IsLinked);
    }

    [Fact]
    public void User_IsLinked_ReturnsFalseWhenProviderSubjectIdIsNull()
    {
        // Arrange
        var user = new User
        {
            ProviderSubjectId = null
        };

        // Assert
        Assert.False(user.IsLinked);
    }

    [Fact]
    public void User_IsLinked_ReturnsFalseWhenProviderSubjectIdIsEmpty()
    {
        // Arrange
        var user = new User
        {
            ProviderSubjectId = string.Empty
        };

        // Assert
        Assert.False(user.IsLinked);
    }

    [Fact]
    public void User_Properties_CanBeSetAndGet()
    {
        // Arrange
        var workspace = new Workspace { Id = 1, Name = "Test Workspace" };
        var createdAt = DateTime.UtcNow;

        // Act
        var user = new User
        {
            Id = 1,
            ActiveWorkspaceId = 1,
            Email = "test@example.com",
            IdentityProvider = IdentityProvider.Google,
            ProviderSubjectId = "google-sub-123",
            CreatedAt = createdAt,
            ActiveWorkspace = workspace
        };

        // Assert
        Assert.Equal(1, user.Id);
        Assert.Equal(1, user.ActiveWorkspaceId);
        Assert.Equal("test@example.com", user.Email);
        Assert.Equal(IdentityProvider.Google, user.IdentityProvider);
        Assert.Equal("google-sub-123", user.ProviderSubjectId);
        Assert.Equal(createdAt, user.CreatedAt);
        Assert.Same(workspace, user.ActiveWorkspace);
    }

    [Theory]
    [InlineData(IdentityProvider.Microsoft)]
    [InlineData(IdentityProvider.Google)]
    [InlineData(IdentityProvider.Apple)]
    public void User_IdentityProvider_AcceptsAllValues(IdentityProvider provider)
    {
        // Act
        var user = new User { IdentityProvider = provider };

        // Assert
        Assert.Equal(provider, user.IdentityProvider);
    }
}