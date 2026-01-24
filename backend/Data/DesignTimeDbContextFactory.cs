using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace backend.Data;

/// <summary>
/// Design-time factory for generating migrations targeting SQL Server.
/// Used by EF Core tools when generating migrations and migration bundles.
/// 
/// Usage:
///   dotnet ef migrations add MigrationName
///   dotnet ef migrations bundle --configuration Release --output efbundle.exe
/// </summary>
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<AppDbContext>
{
    public AppDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<AppDbContext>();
        
        // Use local SQL Server for design-time operations
        optionsBuilder.UseSqlServer("Server=localhost,1433;Database=onebighead;User Id=sa;Password=DevPassword123!;TrustServerCertificate=True");
        
        return new AppDbContext(optionsBuilder.Options);
    }
}
