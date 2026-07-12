using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace OneBigHead.Server.Data;

/// <summary>
/// Design-time factory for generating migrations targeting PostgreSQL.
/// Used by EF Core tools when generating migrations and migration bundles.
///
/// Usage:
///   dotnet ef migrations add MigrationName
///   dotnet ef migrations bundle --configuration Release --output efbundle
/// </summary>
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<AppDbContext>
{
    public AppDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<AppDbContext>();

        // Use local PostgreSQL for design-time operations
        optionsBuilder.UseNpgsql("Host=localhost;Port=5432;Database=onebighead;Username=postgres;Password=DevPassword123!");

        return new AppDbContext(optionsBuilder.Options);
    }
}
