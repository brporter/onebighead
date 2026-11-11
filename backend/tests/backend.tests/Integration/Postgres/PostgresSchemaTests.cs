using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration.Postgres;

/// <summary>
/// Verifies the generated InitialCreate migration produces a working schema
/// on a real PostgreSQL server.
/// </summary>
[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class PostgresSchemaTests : IAsyncLifetime
{
    private readonly PostgresIntegrationFixture _fixture;

    public PostgresSchemaTests(PostgresIntegrationFixture fixture)
    {
        _fixture = fixture;
    }

    public Task InitializeAsync() => _fixture.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Migrations_ApplyCleanly_WithNonePending()
    {
        await using var context = _fixture.CreateContext();

        var pending = await context.Database.GetPendingMigrationsAsync();

        Assert.Empty(pending);
    }

    [Fact]
    public async Task OptionalWorkspaceMigration_CanBeReversedWithoutChangingExistingAccounts()
    {
        await using var context = _fixture.CreateContext();
        context.Workspaces.Add(new Workspace { Id = 1, Name = "Keep" });
        context.Users.Add(new User { Id = 1, ActiveWorkspaceId = 1, Email = "keep@example.test" });
        await context.SaveChangesAsync();
        var migrations = (await context.Database.GetAppliedMigrationsAsync()).ToArray();
        var migrator = context.GetService<IMigrator>();
        try
        {
            await migrator.MigrateAsync(BeforeOptionalWorkspace(migrations));
            var error = await Assert.ThrowsAsync<PostgresException>(() => context.Database.ExecuteSqlRawAsync("""
                INSERT INTO "Users" ("Id", "Email", "IdentityProvider", "IsSystemAdministrator", "IsDeleted", "CreatedAt")
                VALUES (2, 'no-workspace@example.test', 0, false, false, CURRENT_TIMESTAMP)
                """));
            Assert.Equal(PostgresErrorCodes.NotNullViolation, error.SqlState);
        }
        finally { await migrator.MigrateAsync(); }
        context.ChangeTracker.Clear();
        Assert.Equal(1, (await context.Users.SingleAsync()).ActiveWorkspaceId);
        Assert.Empty(await context.Database.GetPendingMigrationsAsync());
    }

    [Fact]
    public async Task ReversingOptionalWorkspaceMigration_RefusesToInventWorkspaceIds()
    {
        await using var context = _fixture.CreateContext();
        context.Users.Add(new User { Id = 1, Email = "no-workspace@example.test" });
        await context.SaveChangesAsync();
        var migrations = (await context.Database.GetAppliedMigrationsAsync()).ToArray();
        var migrator = context.GetService<IMigrator>();
        try
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => migrator.MigrateAsync(BeforeOptionalWorkspace(migrations)));
            Assert.Equal(PostgresErrorCodes.NotNullViolation, error.SqlState);
        }
        finally { await migrator.MigrateAsync(); }
        Assert.Null((await context.Users.AsNoTracking().SingleAsync()).ActiveWorkspaceId);
        Assert.Empty(await context.Database.GetPendingMigrationsAsync());
    }

    private static string BeforeOptionalWorkspace(string[] migrations) =>
        migrations[Array.FindIndex(migrations, migration => migration.EndsWith("_AllowUsersWithoutActiveWorkspace", StringComparison.Ordinal)) - 1];

    [Fact]
    public async Task InvitationMigration_PreservesPendingDetailsWithoutGrantingAccountAccess()
    {
        await using var context = _fixture.CreateContext();
        var migrations = (await context.Database.GetAppliedMigrationsAsync()).ToArray();
        var index = Array.FindIndex(migrations, migration => migration.EndsWith("_SeparateWorkspaceInvitations", StringComparison.Ordinal));
        var migrator = context.GetService<IMigrator>();
        context.Workspaces.Add(new Workspace { Id = 1, Name = "Existing" });
        context.Users.AddRange(new User { Id = 1, Email = "pending@example.test", ActiveWorkspaceId = 1 },
            new User { Id = 2, Email = "PENDING@example.test", ActiveWorkspaceId = 1, ProviderSubjectId = "" },
            new User { Id = 3, Email = "linked@example.test", ActiveWorkspaceId = 1, ProviderSubjectId = "identity" });
        context.WorkspaceUsers.AddRange(new WorkspaceUser { UserId = 1, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.Normal },
            new WorkspaceUser { UserId = 2, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
            new WorkspaceUser { UserId = 3, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
        await context.SaveChangesAsync();
        try { await migrator.MigrateAsync(migrations[index - 1]); }
        finally { await migrator.MigrateAsync(); }
        context.ChangeTracker.Clear();
        Assert.Equal(3, await context.Users.CountAsync());
        Assert.Equal(3, (await context.WorkspaceUsers.SingleAsync()).UserId);
        var invitation = await context.WorkspaceInvitations.SingleAsync();
        Assert.Equal("pending@example.test", invitation.Email);
        Assert.Equal(WorkspaceRole.Normal, invitation.Role);
        Assert.True(invitation.ExpiresAt < DateTime.UtcNow);
        Assert.Null(invitation.AcceptedAt);
    }

    [Fact]
    public async Task AuthenticationStampMigration_BackfillsDistinctStampsAndPreservesExistingAccounts()
    {
        await using var context = _fixture.CreateContext();
        context.Users.AddRange(new User { Id = 1, Email = "first@example.test" }, new User { Id = 2, Email = "second@example.test" });
        await context.SaveChangesAsync();
        var migrations = (await context.Database.GetAppliedMigrationsAsync()).ToArray();
        var index = Array.FindIndex(migrations, migration => migration.EndsWith("_AddAccountAuthenticationStamp", StringComparison.Ordinal));
        var migrator = context.GetService<IMigrator>();
        try { await migrator.MigrateAsync(migrations[index - 1]); }
        finally { await migrator.MigrateAsync(); }
        context.ChangeTracker.Clear();
        var accounts = await context.Users.OrderBy(user => user.Id).ToListAsync();
        Assert.Equal(new[] { "first@example.test", "second@example.test" }, accounts.Select(user => user.Email));
        Assert.All(accounts, user => Assert.NotEqual(Guid.Empty, user.AuthenticationStamp));
        Assert.Equal(2, accounts.Select(user => user.AuthenticationStamp).Distinct().Count());
        Assert.Empty(await context.Database.GetPendingMigrationsAsync());
    }

    [Fact]
    public async Task WelcomeCollectionMigration_PreservesLegacyWelcomeAndCollectionsAcrossUpgradeAndDowngrade()
    {
        await using var context = _fixture.CreateContext();
        context.Workspaces.AddRange(new Workspace { Id = 1, Name = "Completed", HasCompletedWelcome = true },
            new Workspace { Id = 2, Name = "Incomplete" });
        context.Collections.Add(new OneBigHead.Server.Models.Collection { Id = 1, WorkspaceId = 1, Name = "Existing books" });
        await context.SaveChangesAsync();
        var migrations = (await context.Database.GetAppliedMigrationsAsync()).ToArray();
        var index = Array.FindIndex(migrations, migration => migration.EndsWith("_RememberWelcomeCollection", StringComparison.Ordinal));
        var migrator = context.GetService<IMigrator>();
        try { await migrator.MigrateAsync(migrations[index - 1]); }
        finally { await migrator.MigrateAsync(); }
        context.ChangeTracker.Clear();
        var workspaces = await context.Workspaces.OrderBy(w => w.Id).ToListAsync();
        Assert.True(workspaces[0].HasCompletedWelcome);
        Assert.False(workspaces[1].HasCompletedWelcome);
        Assert.All(workspaces, workspace => Assert.Null(workspace.WelcomeCollectionId));
        Assert.Equal("Existing books", (await context.Collections.SingleAsync()).Name);
        Assert.Empty(await context.Database.GetPendingMigrationsAsync());
        Assert.False(context.Database.HasPendingModelChanges());
    }

    [Fact]
    public async Task SetupReceiptMigration_PreservesExistingWorkspacesAndAccountsAcrossUpgradeAndDowngrade()
    {
        await using var context = _fixture.CreateContext();
        context.Workspaces.Add(new Workspace { Id = 1, Name = "Existing", HasCompletedWelcome = true });
        context.Users.Add(new User { Id = 1, Email = "existing@example.test", ActiveWorkspaceId = 1 });
        context.Collections.Add(new OneBigHead.Server.Models.Collection { WorkspaceId = 1, Name = "Existing collection" });
        await context.SaveChangesAsync();
        var migrations = (await context.Database.GetAppliedMigrationsAsync()).ToArray();
        var index = Array.FindIndex(migrations, migration => migration.EndsWith("_PersistWorkspaceSetupRequests", StringComparison.Ordinal));
        var migrator = context.GetService<IMigrator>();
        try { await migrator.MigrateAsync(migrations[index - 1]); }
        finally { await migrator.MigrateAsync(); }
        context.ChangeTracker.Clear();
        Assert.Equal("Existing", (await context.Workspaces.SingleAsync()).Name);
        Assert.Equal(1, (await context.Users.SingleAsync()).ActiveWorkspaceId);
        Assert.Equal("Existing collection", (await context.Collections.SingleAsync()).Name);
        Assert.Empty(await context.WorkspaceSetupReceipts.ToListAsync());
        Assert.False(context.Database.HasPendingModelChanges());
    }

    [Fact]
    public async Task IdentityColumns_GenerateSequentialIds()
    {
        await using var context = _fixture.CreateContext();
        var first = new Workspace { Name = "First" };
        var second = new Workspace { Name = "Second" };
        context.Workspaces.AddRange(first, second);

        await context.SaveChangesAsync();

        Assert.Equal(1, first.Id);
        Assert.Equal(2, second.Id);
    }

    [Fact]
    public async Task WorkspaceSlugIndex_AllowsMultipleNullSlugs()
    {
        await using var context = _fixture.CreateContext();
        context.Workspaces.AddRange(
            new Workspace { Name = "One" },
            new Workspace { Name = "Two" });

        await context.SaveChangesAsync();

        Assert.Equal(2, await context.Workspaces.CountAsync());
    }

    [Fact]
    public async Task WorkspaceSlugIndex_RejectsDuplicateSlugs()
    {
        await using (var context = _fixture.CreateContext())
        {
            context.Workspaces.Add(new Workspace { Name = "One", Slug = "shared" });
            await context.SaveChangesAsync();
        }

        await using (var context = _fixture.CreateContext())
        {
            context.Workspaces.Add(new Workspace { Name = "Two", Slug = "shared" });

            await Assert.ThrowsAsync<DbUpdateException>(() => context.SaveChangesAsync());
        }
    }
}
