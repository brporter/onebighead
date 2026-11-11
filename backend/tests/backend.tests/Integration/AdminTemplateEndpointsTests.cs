using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class AdminTemplateEndpointsTests(CustomWebApplicationFactory factory) : IntegrationTestBase(factory)
{
    private async Task GrantAccessAsync()
    {
        await using var context = GetDbContext();
        (await context.Users.SingleAsync(u => u.Id == DefaultUserId)).IsSystemAdministrator = true;
        await context.SaveChangesAsync();
    }

    public override async Task DisposeAsync()
    {
        await using var context = GetDbContext();
        (await context.Users.SingleAsync(u => u.Id == DefaultUserId)).IsSystemAdministrator = false;
        await context.SaveChangesAsync();
        await base.DisposeAsync();
    }

    protected override async Task SeedAdditionalDataAsync()
    {
        await using var context = GetDbContext();
        if (!await context.ItemTemplates.AnyAsync(t => t.Id == 1000))
        {
            context.ItemTemplates.Add(new ItemTemplate { Id = 1000, WorkspaceId = DefaultWorkspaceId,
                Name = "Private", TemplateKey = Guid.NewGuid() });
            await context.SaveChangesAsync();
        }
    }

    [Fact]
    public async Task SystemAdministrator_CanManageSharedDefinitionsThroughRegisteredService()
    {
        await GrantAccessAsync();
        Client.DefaultRequestHeaders.Add(TestAuthHandler.SystemAdministratorHeader, "true");
        var request = new SystemTemplateRequest { Name = "Reading", Description = "Library",
            Properties = [new() { Category = "Edition", Name = "Publisher" }, new() { Category = "Edition", Name = "Year" }] };
        var createdResponse = await PostJsonAsync("/api/admin/templates", request);
        Assert.Equal(HttpStatusCode.Created, createdResponse.StatusCode);
        var created = (await DeserializeResponseAsync<ItemTemplateResponse>(createdResponse))!;
        Assert.True(created.IsSystem);
        Assert.EndsWith($"/api/Admin/templates/{created.ItemTemplateId}", createdResponse.Headers.Location!.AbsolutePath, StringComparison.OrdinalIgnoreCase);
        var readResponse = await Client.GetAsync(createdResponse.Headers.Location);
        readResponse.EnsureSuccessStatusCode();
        var read = (await DeserializeResponseAsync<ItemTemplateResponse>(readResponse))!;
        Assert.Equal(created.TemplateKey, read.TemplateKey);
        Assert.Equal(new[] { "Publisher", "Year" }, read.Properties.Select(p => p.Name));

        var catalog = (await DeserializeResponseAsync<List<ItemTemplateResponse>>(await Client.GetAsync("/api/admin/templates")))!;
        Assert.Contains(catalog, t => t.ItemTemplateId == created.ItemTemplateId);
        Assert.DoesNotContain(catalog, t => t.ItemTemplateId == 1000);

        request.Name = "Revised reading";
        request.Properties = [new() { Category = "Publication", Name = "Edition" }];
        var updatedResponse = await PutJsonAsync($"/api/admin/templates/{created.ItemTemplateId}", request);
        updatedResponse.EnsureSuccessStatusCode();
        var updated = (await DeserializeResponseAsync<ItemTemplateResponse>(updatedResponse))!;
        Assert.Equal(created.TemplateKey, updated.TemplateKey);
        Assert.Equal("Edition", Assert.Single(updated.Properties).Name);
        Assert.Equal(request.Name, updated.Name);

        Assert.Equal(HttpStatusCode.NoContent, (await Client.DeleteAsync($"/api/admin/templates/{created.ItemTemplateId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Client.GetAsync($"/api/admin/templates/{created.ItemTemplateId}")).StatusCode);
    }

    [Theory]
    [InlineData(1000)]
    [InlineData(99999)]
    public async Task MissingAndWorkspaceOwnedDefinitions_ReturnNotFound(int id)
    {
        await GrantAccessAsync();
        Client.DefaultRequestHeaders.Add(TestAuthHandler.SystemAdministratorHeader, "true");
        Assert.Equal(HttpStatusCode.NotFound, (await Client.GetAsync($"/api/admin/templates/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await PutJsonAsync($"/api/admin/templates/{id}", new SystemTemplateRequest { Name = "Changed" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Client.DeleteAsync($"/api/admin/templates/{id}")).StatusCode);
        await using var context = GetDbContext();
        Assert.Equal("Private", (await context.ItemTemplates.SingleAsync(t => t.Id == 1000)).Name);
    }

    [Theory]
    [InlineData("GET", "/api/admin/templates")]
    [InlineData("GET", "/api/admin/templates/1")]
    [InlineData("POST", "/api/admin/templates")]
    [InlineData("PUT", "/api/admin/templates/1")]
    [InlineData("DELETE", "/api/admin/templates/1")]
    public async Task EveryTemplateEndpoint_RequiresSystemAdministratorRole(string method, string path)
    {
        using var anonymous = CreateAnonymousClient();
        using var normal = CreateNormalUserClient();
        foreach (var client in new[] { anonymous, normal, Client })
        {
            using var request = new HttpRequestMessage(new HttpMethod(method), path)
            { Content = JsonContent.Create(new SystemTemplateRequest { Name = "Unauthorized change" }) };
            var response = await client.SendAsync(request);
            Assert.Equal(client == anonymous ? HttpStatusCode.Unauthorized : HttpStatusCode.Forbidden, response.StatusCode);
        }
        await using var context = GetDbContext();
        Assert.Equal("General Item", (await context.ItemTemplates.SingleAsync(t => t.Id == 1)).Name);
        Assert.False(await context.ItemTemplates.AnyAsync(t => t.Name == "Unauthorized change"));
    }

    [Theory]
    [InlineData("POST", "/api/admin/templates")]
    [InlineData("PUT", "/api/admin/templates/1")]
    public async Task InvalidDefinition_ReturnsValidationErrorsWithoutPersisting(string method, string path)
    {
        await GrantAccessAsync();
        Client.DefaultRequestHeaders.Add(TestAuthHandler.SystemAdministratorHeader, "true");
        using var request = new HttpRequestMessage(new HttpMethod(method), path)
        { Content = JsonContent.Create(new SystemTemplateRequest { Name = "", Properties = [new() { Category = "Details", Name = "" }] }) };
        Assert.Equal(HttpStatusCode.BadRequest, (await Client.SendAsync(request)).StatusCode);
        await using var context = GetDbContext();
        Assert.Equal("General Item", (await context.ItemTemplates.SingleAsync(t => t.Id == 1)).Name);
    }
}
