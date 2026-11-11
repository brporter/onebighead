using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Workspaces;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class WorkspaceRestorationServiceTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var context = fixture.CreateContext();
        context.Workspaces.AddRange(Enumerable.Range(1, 3).Select(id => new Workspace
        {
            Id = id, Name = $"Workspace {id}", IsDeleted = id > 1,
            DeletedAt = id > 1 ? DateTime.UtcNow.AddDays(-2) : null, DeletedByUserId = id > 1 ? 1 : null
        }));
        context.Users.Add(new User { Id = 1, ActiveWorkspaceId = 1, Email = "collector@example.com" });
        context.WorkspaceUsers.AddRange(Enumerable.Range(1, 3).Select(id => new WorkspaceUser
        {
            UserId = 1, WorkspaceId = id, WorkspaceRole = WorkspaceRole.WorkspaceAdmin
        }));
        await context.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Batch_CommitsRestorationMetadataAndActiveWorkspaceTogether()
    {
        var service = new WorkspaceRestorationService(fixture.CreateContextFactory(), NullLogger<WorkspaceRestorationService>.Instance);
        var result = await service.RestoreAndActivateAsync(1, [1, 3, 2, 3]);
        Assert.True(result.IsAuthorized);
        Assert.Equal(new[] { 3, 2 }, result.RestoredWorkspaces.Select(w => w.Id));
        Assert.Equal(3, result.ActiveUser!.ActiveWorkspaceId);

        await using var context = fixture.CreateContext();
        Assert.Equal(3, (await context.Users.SingleAsync()).ActiveWorkspaceId);
        Assert.All(await context.Workspaces.ToListAsync(), workspace =>
        {
            Assert.False(workspace.IsDeleted);
            Assert.Null(workspace.DeletedAt);
            Assert.Null(workspace.DeletedByUserId);
        });
    }

    [Fact]
    public async Task LaterDatabaseFailure_RollsBackAlreadyExecutedWorkspaceAndSessionUpdates()
    {
        await using var context = fixture.CreateContext();
        // The existing deleted row satisfies this constraint; restoring it fails.
        await context.Database.ExecuteSqlRawAsync("""
            ALTER TABLE "Workspaces" ADD CONSTRAINT "RestorationRollbackTest"
            CHECK ("Id" <> 3 OR "IsDeleted")
            """);
        try
        {
            var commands = new CompletedUpdates();
            var options = new DbContextOptionsBuilder<AppDbContext>()
                .UseNpgsql(fixture.ConnectionString, postgres => postgres.MaxBatchSize(1))
                .AddInterceptors(commands).Options;
            var logger = new Mock<ILogger<WorkspaceRestorationService>>(MockBehavior.Strict);
            var service = new WorkspaceRestorationService(new TestDbContextFactory(options), logger.Object);

            await Assert.ThrowsAsync<DbUpdateException>(() => service.RestoreAndActivateAsync(1, [2, 3]));
            // Prove that failure occurred after SQL updates, not before any write.
            Assert.Contains(commands.Tables, table => table == "Workspaces");
            Assert.Contains(commands.Tables, table => table == "Users");
            logger.VerifyNoOtherCalls(); // Never log successful restores before commit.

            Assert.Equal(1, (await context.Users.SingleAsync()).ActiveWorkspaceId);
            Assert.All(await context.Workspaces.Where(w => w.Id > 1).ToListAsync(), workspace =>
            {
                Assert.True(workspace.IsDeleted);
                Assert.NotNull(workspace.DeletedAt);
                Assert.Equal(1, workspace.DeletedByUserId);
            });
        }
        finally
        {
            await context.Database.ExecuteSqlRawAsync("""
                ALTER TABLE "Workspaces" DROP CONSTRAINT "RestorationRollbackTest"
                """, CancellationToken.None);
        }
    }

}
