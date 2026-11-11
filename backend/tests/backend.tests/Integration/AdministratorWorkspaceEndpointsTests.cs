using System.Net;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Moq;
using OneBigHead.Server.Services.Administration;

namespace OneBigHead.Server.Tests.Integration;

public class AdministratorWorkspaceEndpointsTests(CustomWebApplicationFactory factory) : IntegrationTestBase(factory)
{
    [Theory]
    [InlineData(AdministratorWorkspaceDeletionResult.Deleted, HttpStatusCode.NoContent)]
    [InlineData(AdministratorWorkspaceDeletionResult.NotFound, HttpStatusCode.NotFound)]
    [InlineData(AdministratorWorkspaceDeletionResult.ConflictingReferences, HttpStatusCode.Conflict)]
    [InlineData(AdministratorWorkspaceDeletionResult.ConcurrentChange, HttpStatusCode.Conflict)]
    public async Task Delete_DelegatesToTheAtomicCommandAndMapsItsOutcome(AdministratorWorkspaceDeletionResult result, HttpStatusCode status)
    {
        var command = new Mock<IAdministratorWorkspaceDeletion>(MockBehavior.Strict);
        command.Setup(c => c.DeleteAsync(42)).ReturnsAsync(result);
        await using var app = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IAdministratorWorkspaceDeletion>();
            services.AddSingleton(command.Object);
        }));
        await using (var context = GetDbContext())
        {
            (await context.Users.SingleAsync(u => u.Id == DefaultUserId)).IsSystemAdministrator = true;
            await context.SaveChangesAsync();
        }
        using var client = app.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, DefaultUserId.ToString());
        client.DefaultRequestHeaders.Add(TestAuthHandler.WorkspaceIdHeader, DefaultWorkspaceId.ToString());
        client.DefaultRequestHeaders.Add(TestAuthHandler.EmailHeader, DefaultEmail);
        var response = await client.DeleteAsync("/api/admin/workspaces/42");
        Assert.Equal(status, response.StatusCode);
        command.Verify(c => c.DeleteAsync(42), Times.Once);
        if (result == AdministratorWorkspaceDeletionResult.ConflictingReferences)
            Assert.Contains("Resolve those references", await response.Content.ReadAsStringAsync());
        if (result == AdministratorWorkspaceDeletionResult.ConcurrentChange)
            Assert.Contains("Reload and try again", await response.Content.ReadAsStringAsync());
    }
}
