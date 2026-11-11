using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OneBigHead.Server.Data;

namespace OneBigHead.Server.Tests.Integration.Postgres;

/// <summary>Exercises registered membership commands against the collection's disposable database.</summary>
internal sealed class MembershipWebApplicationFactory(string connection) : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureTestServices(services =>
        {
            services.AddDbContextFactory<AppDbContext>(options => options.UseNpgsql(connection));
            services.AddAuthentication(TestAuthHandler.SchemeName)
                .AddScheme<TestAuthSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, _ => { });
        });
    }
}
