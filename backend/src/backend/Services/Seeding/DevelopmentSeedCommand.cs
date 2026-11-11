#if DEBUG
namespace OneBigHead.Server.Services.Seeding;

/// <summary>Development-only command; never compiled into a Release deployment.</summary>
internal static class DevelopmentSeedCommand
{
    public static (bool Requested, string[] HostArguments) ReadArguments(string[] args)
        => (args.Contains("--seed"), args.Where(arg => arg != "--seed").ToArray());

    public static async Task<int> ExecuteAsync(IConfiguration configuration, IHostEnvironment environment,
        ILoggerFactory loggerFactory)
    {
        var configuredPath = configuration["Seeding:Path"] ?? "seeds";
        var seedsPath = Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.GetFullPath(Path.Combine(environment.ContentRootPath, configuredPath));
        var logger = loggerFactory.CreateLogger<JsonDatabaseSeeder>();
        var seeder = new JsonDatabaseSeeder(seedsPath, logger);
        if (seeder.GetSeedFiles().Count == 0)
        {
            logger.LogError("No seed files found in {SeedsPath}. Check the Seeding:Path setting.", seedsPath);
            return 1;
        }

        var connectionString = configuration.GetConnectionString("DefaultConnection")
            ?? throw new InvalidOperationException("ConnectionStrings:DefaultConnection is not configured.");
        await seeder.SeedAsync(connectionString);
        return 0;
    }
}
#endif
