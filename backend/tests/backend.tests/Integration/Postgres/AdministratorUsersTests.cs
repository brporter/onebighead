using Microsoft.EntityFrameworkCore;
using Npgsql;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Administration;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class AdministratorUsersTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private AdministratorUsers Commands() => new(fixture.CreateContextFactory());

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var context = fixture.CreateContext();
        context.Workspaces.Add(new Workspace { Id = 1, Name = "Shared workspace" });
        context.Users.AddRange(new User { Id = 1, ActiveWorkspaceId = 1, Email = "reader@example.test" },
            new User { Id = 2, ActiveWorkspaceId = 1, Email = "admin@example.test", IsSystemAdministrator = true });
        context.WorkspaceUsers.AddRange(new WorkspaceUser { UserId = 1, WorkspaceId = 1 }, new WorkspaceUser { UserId = 2, WorkspaceId = 1 });
        context.SupportRequests.Add(new SupportRequest { Id = 1, UserId = 1, Email = "reader@example.test", Subject = "Help", Description = "Question" });
        context.SupportReplies.Add(new SupportReply { SupportRequestId = 1, UserId = 1, Message = "More context" });
        await context.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task StatusChanges_PersistAndImmediatelyAffectCurrentAuthorization()
    {
        var access = new AdministratorAccessService(fixture.CreateContextFactory());
        var enabled = await Commands().SetAdministratorAsync(1, true);
        Assert.NotNull(enabled);
        Assert.True(enabled.IsSystemAdministrator);
        Assert.Equal("reader@example.test", enabled.Email);
        Assert.Equal("Shared workspace", enabled.WorkspaceName);
        Assert.True(await access.HasAccessAsync(1));
        var disabled = await Commands().SetAdministratorAsync(1, false);
        Assert.NotNull(disabled);
        Assert.False(disabled.IsSystemAdministrator);
        Assert.False(await access.HasAccessAsync(1));
        Assert.True(await access.HasAccessAsync(2));
    }

    [Fact]
    public async Task MissingUser_ReturnsNotFoundWithoutChangingOtherAccounts()
    {
        Assert.Null(await Commands().SetAdministratorAsync(999, true));
        Assert.False(await Commands().DeleteAsync(999));
        await using var context = fixture.CreateContext();
        Assert.Equal(2, await context.Users.CountAsync());
        Assert.False((await context.Users.SingleAsync(u => u.Id == 1)).IsSystemAdministrator);
    }

    [Fact]
    public async Task Deletion_RemovesMembershipsButPreservesSupportHistoryAndOtherUsers()
    {
        Assert.True(await Commands().DeleteAsync(1));
        await using var context = fixture.CreateContext();
        Assert.Equal(2, (await context.Users.SingleAsync()).Id);
        Assert.Equal(2, (await context.WorkspaceUsers.SingleAsync()).UserId);
        Assert.Single(await context.Workspaces.ToListAsync());
        var request = await context.SupportRequests.SingleAsync();
        Assert.Null(request.UserId);
        Assert.Equal("Help", request.Subject);
        var reply = await context.SupportReplies.SingleAsync();
        Assert.Null(reply.UserId);
        Assert.Equal("More context", reply.Message);
        Assert.False(await new AdministratorAccessService(fixture.CreateContextFactory()).HasAccessAsync(1));
    }

    [Fact]
    public async Task FailedStatusChange_PreservesThePreviousPermission()
    {
        await using var context = fixture.CreateContext();
        await context.Database.ExecuteSqlRawAsync("ALTER TABLE \"Users\" ADD CONSTRAINT reject_admin_promotion CHECK (\"Id\" <> 1 OR NOT \"IsSystemAdministrator\")");
        try
        {
            await Assert.ThrowsAsync<DbUpdateException>(() => Commands().SetAdministratorAsync(1, true));
            Assert.False(await new AdministratorAccessService(fixture.CreateContextFactory()).HasAccessAsync(1));
        }
        finally
        {
            await context.Database.ExecuteSqlRawAsync("ALTER TABLE \"Users\" DROP CONSTRAINT reject_admin_promotion");
        }
    }

    [Fact]
    public async Task FailedDeletion_RollsBackMembershipAndSupportChangesAfterTheyExecute()
    {
        await using var context = fixture.CreateContext();
        await context.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION reject_admin_user_deletion() RETURNS trigger AS $$
            BEGIN
                IF EXISTS (SELECT 1 FROM "WorkspaceUsers" WHERE "UserId" = OLD."Id")
                   OR EXISTS (SELECT 1 FROM "SupportRequests" WHERE "UserId" = OLD."Id")
                   OR EXISTS (SELECT 1 FROM "SupportReplies" WHERE "UserId" = OLD."Id") THEN
                    RAISE EXCEPTION 'Dependent changes have not executed';
                END IF;
                RAISE EXCEPTION 'Failure after dependent changes' USING ERRCODE = '23514';
            END;
            $$ LANGUAGE plpgsql
            """);
        await context.Database.ExecuteSqlRawAsync("CREATE TRIGGER z_reject_admin_user_deletion AFTER DELETE ON \"Users\" FOR EACH ROW EXECUTE FUNCTION reject_admin_user_deletion()");
        try
        {
            var error = await Assert.ThrowsAsync<DbUpdateException>(() => Commands().DeleteAsync(1));
            var databaseError = Assert.IsType<PostgresException>(error.InnerException);
            Assert.Equal(PostgresErrorCodes.CheckViolation, databaseError.SqlState);
            Assert.Contains("Failure after dependent changes", databaseError.MessageText);
            Assert.True(await context.Users.AnyAsync(u => u.Id == 1));
            Assert.True(await context.WorkspaceUsers.AnyAsync(u => u.UserId == 1));
            Assert.Equal(1, (await context.SupportRequests.SingleAsync()).UserId);
            Assert.Equal(1, (await context.SupportReplies.SingleAsync()).UserId);
        }
        finally
        {
            await context.Database.ExecuteSqlRawAsync("DROP TRIGGER z_reject_admin_user_deletion ON \"Users\"");
            await context.Database.ExecuteSqlRawAsync("DROP FUNCTION reject_admin_user_deletion()");
        }
    }
}
