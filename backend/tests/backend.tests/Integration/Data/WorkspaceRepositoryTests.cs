using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Tests.Integration.Data;

[Trait("Category", "Integration")]
public class WorkspaceRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly WorkspaceRepository _repository;

    public WorkspaceRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _repository = new WorkspaceRepository(new TestDbContextFactory(options));
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    private async Task<Workspace> CreateTestWorkspaceAsync(string name = "Test Workspace", bool hasCompletedWelcome = false)
    {
        var workspace = new Workspace
        {
            Name = name,
            HasCompletedWelcome = hasCompletedWelcome,
            CreatedAt = DateTime.UtcNow
        };
        _context.Workspaces.Add(workspace);
        await _context.SaveChangesAsync();
        return workspace;
    }

    #region GetByIdAsync Tests

    [Fact]
    public async Task GetByIdAsync_ReturnsWorkspace_WhenExists()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync("Test Workspace", false);

        // Act
        var result = await _repository.GetByIdAsync(workspace.Id);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Test Workspace", result.Name);
        Assert.False(result.HasCompletedWelcome);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenNotExists()
    {
        // Act
        var result = await _repository.GetByIdAsync(999);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region UpdateAsync Tests

    [Fact]
    public async Task UpdateAsync_SavesChanges()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync("Original Name", false);

        // Act
        workspace.Name = "Updated Name";
        workspace.HasCompletedWelcome = true;
        await _repository.UpdateAsync(workspace);

        // Assert - refetch to confirm changes were saved
        var updated = await _context.Workspaces.FindAsync(workspace.Id);
        Assert.NotNull(updated);
        Assert.Equal("Updated Name", updated.Name);
        Assert.True(updated.HasCompletedWelcome);
    }

    [Fact]
    public async Task UpdateAsync_UpdatesHasCompletedWelcome()
    {
        // Arrange
        var workspace = await CreateTestWorkspaceAsync("Test", false);

        // Act
        workspace.HasCompletedWelcome = true;
        await _repository.UpdateAsync(workspace);

        // Assert
        var result = await _repository.GetByIdAsync(workspace.Id);
        Assert.NotNull(result);
        Assert.True(result.HasCompletedWelcome);
    }

    #endregion
}
