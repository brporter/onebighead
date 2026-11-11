using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Administration;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class AdministratorAccessServiceTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var context = fixture.CreateContext();
        context.Workspaces.Add(new Workspace { Id = 1, Name = "Workspace" });
        context.Users.AddRange(new User { Id = 1, ActiveWorkspaceId = 1, Email = "subject@example.test" },
            new User { Id = 2, ActiveWorkspaceId = 1, Email = "other@example.test", IsSystemAdministrator = true });
        await context.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task EveryRead_UsesTheCurrentTargetAccountAndExcludesDeletedOrMissingUsers()
    {
        var service = new AdministratorAccessService(fixture.CreateContextFactory());
        Assert.False(await service.HasAccessAsync(1));
        Assert.True(await service.HasAccessAsync(2));
        await using var context = fixture.CreateContext();
        var user = await context.Users.SingleAsync(u => u.Id == 1);
        user.IsSystemAdministrator = true;
        await context.SaveChangesAsync();
        Assert.True(await service.HasAccessAsync(1));
        user.IsSystemAdministrator = false;
        await context.SaveChangesAsync();
        Assert.False(await service.HasAccessAsync(1));
        user.IsSystemAdministrator = true;
        user.IsDeleted = true;
        await context.SaveChangesAsync();
        Assert.False(await service.HasAccessAsync(1));
        context.Users.Remove(user);
        await context.SaveChangesAsync();
        Assert.False(await service.HasAccessAsync(1));
        Assert.False(await service.HasAccessAsync(999));
        Assert.True(await service.HasAccessAsync(2));
    }
}
