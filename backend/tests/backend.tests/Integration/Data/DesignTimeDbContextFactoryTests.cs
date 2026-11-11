using Microsoft.EntityFrameworkCore;
using Npgsql;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration.Data;

public class DesignTimeDbContextFactoryTests
{
    [Fact]
    public void CreatesThePostgresMigrationModelWithoutOpeningAConnection()
    {
        using var context = new DesignTimeDbContextFactory().CreateDbContext([]);
        Assert.Equal("Npgsql.EntityFrameworkCore.PostgreSQL", context.Database.ProviderName);
        var connection = context.Database.GetDbConnection();
        Assert.Equal(System.Data.ConnectionState.Closed, connection.State);
        var settings = new NpgsqlConnectionStringBuilder(connection.ConnectionString);
        Assert.Equal("localhost", settings.Host);
        Assert.Equal("onebighead", settings.Database);
        Assert.NotNull(context.Model.FindEntityType(typeof(Collection)));
        Assert.NotEmpty(context.Database.GetMigrations());
    }
}
