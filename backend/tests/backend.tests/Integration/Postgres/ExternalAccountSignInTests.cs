using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
public partial class ExternalAccountSignInTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    public Task InitializeAsync() => fixture.ResetAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData(IdentityProvider.Microsoft, "original", false)]
    [InlineData(IdentityProvider.Microsoft, "original", true)]
    [InlineData(IdentityProvider.Google, "different", false)]
    [InlineData(IdentityProvider.Google, "different", true)]
    public async Task MatchingEmail_DoesNotAuthorizeAnotherProviderOrSubject(IdentityProvider provider, string subject, bool deleted)
    {
        await SeedAccount(IdentityProvider.Google, "original", deleted);
        var result = await Service().GetOrCreateAsync(provider, Identity(subject));
        Assert.NotNull(result.User);
        Assert.NotEqual(1, result.User.Id);
        Assert.False(result.User.IsSystemAdministrator);
        Assert.NotEqual(1, result.User.ActiveWorkspaceId);
        await using var check = fixture.CreateContext();
        var account = await check.Users.SingleAsync(user => user.Id == 1);
        Assert.Equal(IdentityProvider.Google, account.IdentityProvider);
        Assert.Equal("original", account.ProviderSubjectId);
        Assert.Equal(deleted, account.IsDeleted);
        Assert.Equal(2, await check.Workspaces.CountAsync());
        Assert.False(await check.WorkspaceUsers.AnyAsync(member => member.UserId == result.User.Id && member.WorkspaceId == 1));
    }

    [Fact]
    public async Task Restoration_DoesNotUndoConcurrentAdministratorRevocation()
    {
        await SeedAccount(IdentityProvider.Google, "original", deleted: true);
        var change = new BeforeMembershipSave(async () =>
        {
            await using var context = fixture.CreateContext();
            await context.Users.ExecuteUpdateAsync(set => set.SetProperty(user => user.IsSystemAdministrator, false));
        });

        var result = await Service(change).GetOrCreateAsync(IdentityProvider.Google, Identity("original"));
        Assert.Null(result.User);
        await using var check = fixture.CreateContext();
        var account = await check.Users.SingleAsync();
        Assert.False(account.IsSystemAdministrator);
        Assert.True(account.IsDeleted);
    }

    [Fact]
    public async Task DifferentProviderIdentities_CannotClaimTheSamePendingAccount()
    {
        await SeedAccount(IdentityProvider.None, null);
        var google = await Service().GetOrCreateAsync(IdentityProvider.Google, Identity("google"));
        var microsoft = await Service().GetOrCreateAsync(IdentityProvider.Microsoft, Identity("microsoft"));
        Assert.NotEqual(1, google.User!.Id);
        Assert.NotEqual(1, microsoft.User!.Id);
        Assert.NotEqual(google.User.Id, microsoft.User.Id);
        await using var check = fixture.CreateContext();
        var pending = await check.Users.SingleAsync(user => user.Id == 1);
        Assert.Equal(IdentityProvider.None, pending.IdentityProvider);
        Assert.Null(pending.ProviderSubjectId);
        Assert.Single(await check.WorkspaceUsers.Where(member => member.WorkspaceId == 1).ToListAsync());
    }

    private async Task SeedAccount(IdentityProvider provider, string? subject, bool deleted = false)
    {
        await using var context = fixture.CreateContext();
        var workspace = new Workspace { Name = "Existing" };
        var user = new User { Email = "owner@example.test", IdentityProvider = provider, ProviderSubjectId = subject,
            ActiveWorkspace = workspace, IsDeleted = deleted, DeletedAt = deleted ? DateTime.UtcNow : null,
            IsSystemAdministrator = true, AcceptedTermsAt = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc) };
        context.WorkspaceUsers.Add(new WorkspaceUser { User = user, Workspace = workspace, WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
        await context.SaveChangesAsync();
    }

    private ExternalUserService Service(params IInterceptor[] interceptors)
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(fixture.ConnectionString).AddInterceptors(interceptors).Options;
        var contexts = new TestDbContextFactory(options);
        return new ExternalUserService(contexts, TimeProvider.System, NullLogger<ExternalUserService>.Instance);
    }

    private static OidcValidationResult Identity(string subject = "original", string email = "owner@example.test")
        => new() { IsValid = true, Subject = subject, Email = email };
}
