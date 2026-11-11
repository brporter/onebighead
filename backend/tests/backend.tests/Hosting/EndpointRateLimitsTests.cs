using System.Net;
using Microsoft.AspNetCore.TestHost;
using OneBigHead.Server.Hosting;

namespace OneBigHead.Server.Tests.Hosting;

public class EndpointRateLimitsTests
{
    [Theory]
    [InlineData("auth-login", 10, null)]
    [InlineData("auth-login", 10, "192.0.2.1")]
    [InlineData("auth-callback", 20, null)]
    [InlineData("auth-callback", 20, "192.0.2.1")]
    [InlineData("public-read", 60, null)]
    [InlineData("public-read", 60, "192.0.2.1")]
    public async Task Policies_RejectAboveLimit_AndKeepDifferentClientsIndependent(string policy, int limit, string? address)
    {
        var builder = StartupTests.CreateBuilder("Testing");
        builder.Services.AddEndpointRateLimits();
        await using var app = builder.Build();
        app.Use((context, next) =>
        {
            var ip = context.Request.Headers["X-Test-IP"].ToString();
            context.Connection.RemoteIpAddress = string.IsNullOrEmpty(ip) ? null : IPAddress.Parse(ip);
            return next(context);
        });
        app.UseRouting();
        app.UseRateLimiter();
        app.MapGet("/limited", () => Results.Ok()).RequireRateLimiting(policy);
        app.MapGet("/health", () => Results.Ok());
        await app.StartAsync();
        using var client = app.GetTestClient();
        if (address is not null) client.DefaultRequestHeaders.Add("X-Test-IP", address);

        for (var count = 0; count < limit; count++)
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/limited")).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.GetAsync("/limited")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health")).StatusCode);

        client.DefaultRequestHeaders.Remove("X-Test-IP");
        client.DefaultRequestHeaders.Add("X-Test-IP", "192.0.2.2");
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/limited")).StatusCode);
        await app.StopAsync();
    }
}
