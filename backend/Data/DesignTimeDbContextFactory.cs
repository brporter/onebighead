using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace backend.Data;

/// <summary>
/// Design-time factory for generating migrations targeting SQL Server.
/// Used by EF Core tools when generating migration scripts for production deployment.
/// 
/// Usage:
///   dotnet ef migrations script --idempotent -o ../publish/migrate.sql
/// 
/// The factory uses SQL Server by default for design-time operations, which enables
/// generating idempotent migration scripts for SQL Azure deployment.
/// </summary>
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<AppDbContext>
{
    public AppDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<AppDbContext>();
        
        // Use SQL Server for design-time operations (migration script generation)
        // The connection string doesn't need to be valid - it's only used to determine the provider
        optionsBuilder.UseSqlServer("Server=.;Database=DesignTime;Trusted_Connection=True;TrustServerCertificate=True");
        
        return new AppDbContext(optionsBuilder.Options);
    }
}
