using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Models;

[Trait("Category", "Unit")]
public class WorkspaceTests
{
    [Fact]
    public void Workspace_DefaultValues_AreCorrect()
    {
        // Act
        var workspace = new Workspace();

        // Assert
        Assert.Equal(0, workspace.Id);
        Assert.Equal(string.Empty, workspace.Name);
        Assert.NotNull(workspace.ActiveUsers);
        Assert.Empty(workspace.ActiveUsers);
        Assert.NotNull(workspace.WorkspaceUsers);
        Assert.Empty(workspace.WorkspaceUsers);
        Assert.NotNull(workspace.Categories);
        Assert.Empty(workspace.Categories);
        Assert.NotNull(workspace.Collections);
        Assert.Empty(workspace.Collections);
    }

    [Fact]
    public void Workspace_Properties_CanBeSetAndGet()
    {
        // Arrange
        var activeUsers = new List<User> { new() { Email = "test@example.com" } };
        var workspaceUsers = new List<WorkspaceUser> { new() { UserId = 1, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.Normal } };
        var categories = new List<Category> { new() { Name = "Cat1" } };
        var collections = new List<Collection> { new() { Name = "Col1", Slug = "col1" } };
        var createdAt = DateTime.UtcNow;

        // Act
        var workspace = new Workspace
        {
            Id = 1,
            Name = "Test Workspace",
            CreatedAt = createdAt,
            ActiveUsers = activeUsers,
            WorkspaceUsers = workspaceUsers,
            Categories = categories,
            Collections = collections
        };

        // Assert
        Assert.Equal(1, workspace.Id);
        Assert.Equal("Test Workspace", workspace.Name);
        Assert.Equal(createdAt, workspace.CreatedAt);
        Assert.Same(activeUsers, workspace.ActiveUsers);
        Assert.Same(workspaceUsers, workspace.WorkspaceUsers);
        Assert.Same(categories, workspace.Categories);
        Assert.Same(collections, workspace.Collections);
    }
}