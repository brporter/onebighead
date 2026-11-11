using System.IdentityModel.Tokens.Jwt;
using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OneBigHead.Server.Authentication;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Memberships;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
public partial class AccountSessionTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var context = fixture.CreateContext();
        context.Workspaces.Add(new Workspace { Id = 1, Name = "Sessions" });
        context.Users.AddRange(new User { Id = 1, Email = "owner@example.test", ActiveWorkspaceId = 1 },
            new User { Id = 2, Email = "member@example.test", ActiveWorkspaceId = 1 });
        context.WorkspaceUsers.AddRange(new WorkspaceUser { UserId = 1, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.WorkspaceAdmin },
            new WorkspaceUser { UserId = 2, WorkspaceId = 1, WorkspaceRole = WorkspaceRole.WorkspaceAdmin });
        await context.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PermissionChange_RejectsOldSnapshotEvenWhenCookieIsSignedAfterCommit(bool signAfterCommit)
    {
        await using var factory = new MembershipWebApplicationFactory(fixture.ConnectionString);
        await using var host = factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.Configure<AuthenticationOptions>(options =>
            {
                options.DefaultAuthenticateScheme = CookieJwtAuthenticationExtensions.SchemeName;
                options.DefaultChallengeScheme = CookieJwtAuthenticationExtensions.SchemeName;
            })));
        using var client = host.CreateClient();
        var tokens = host.Services.GetRequiredService<ITokenService>();
        var reader = host.Services.GetRequiredService<ICurrentUserSessionReader>();
        var snapshot = (await reader.ReadAsync(2))!;
        var original = tokens.GenerateAppToken(snapshot.User, snapshot.Response.WorkspaceRole);
        var issuedAt = new JwtSecurityTokenHandler().ReadJwtToken(original).IssuedAt;
        var command = new TeamMembershipChanges(fixture.CreateContextFactory(),
            new Clock(issuedAt), NullLogger<TeamMembershipChanges>.Instance);
        Assert.Equal(TeamMembershipStatus.Changed, (await command.ChangeRoleAsync(1, 1, 2, WorkspaceRole.Normal)).Status);
        var stale = signAfterCommit ? tokens.GenerateAppToken(snapshot.User, snapshot.Response.WorkspaceRole) : original;
        var name = host.Services.GetRequiredService<IOptions<AuthenticationSettings>>().Value.Cookie.Name;
        client.DefaultRequestHeaders.Add("Cookie", $"{name}={stale}");
        var rejected = await client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);

        var current = (await reader.ReadAsync(2))!;
        client.DefaultRequestHeaders.Remove("Cookie");
        client.DefaultRequestHeaders.Add("Cookie", $"{name}={tokens.GenerateAppToken(current.User, current.Response.WorkspaceRole)}");
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/auth/me")).StatusCode);
    }

    private sealed class Clock(DateTime instant) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => new(instant);
    }
}
