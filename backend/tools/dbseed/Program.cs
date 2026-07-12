using Microsoft.Extensions.Logging;
using Npgsql;
using OneBigHead.Server.Services.Seeding;

// Database Seed Utility
// Seeds the database with data from external JSON definition files
// Operates idempotently - skips rows that already exist

var seedsPath = args.FirstOrDefault(a => !a.StartsWith("-"))
    ?? Path.Combine(AppContext.BaseDirectory, "seeds");
var force = args.Contains("--force") || args.Contains("-f");
var dryRun = args.Contains("--dry-run");
var verbose = args.Contains("--verbose") || args.Contains("-v");
var help = args.Contains("--help") || args.Contains("-h");

if (help)
{
    Console.WriteLine("Database Seed Utility");
    Console.WriteLine();
    Console.WriteLine("Usage: dbseed [seeds-path] [options]");
    Console.WriteLine();
    Console.WriteLine("Arguments:");
    Console.WriteLine("  seeds-path           Path to seeds directory (default: ./seeds)");
    Console.WriteLine();
    Console.WriteLine("Options:");
    Console.WriteLine("  --force, -f          Skip confirmation prompt");
    Console.WriteLine("  --dry-run            Show what would be seeded without making changes");
    Console.WriteLine("  --verbose, -v        Enable verbose (debug) logging");
    Console.WriteLine("  --help, -h           Show this help message");
    Console.WriteLine();
    Console.WriteLine("Environment:");
    Console.WriteLine("  ConnectionStrings__DefaultConnection   Database connection string");
    Console.WriteLine();
    Console.WriteLine("Seed Files:");
    Console.WriteLine("  Seeds are loaded in alphabetical order from the seeds directory.");
    Console.WriteLine("  Each JSON file defines data for one or more tables.");
    Console.WriteLine("  Use 'checkColumns' (array) for composite key idempotency.");
    Console.WriteLine();
    Console.WriteLine("Example:");
    Console.WriteLine("  dbseed --force");
    Console.WriteLine("  dbseed /path/to/seeds --dry-run");
    return 0;
}

// Get connection string from environment
var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__DefaultConnection");

if (string.IsNullOrEmpty(connectionString))
{
    Console.Error.WriteLine("Error: ConnectionStrings__DefaultConnection environment variable not set.");
    return 1;
}

// Configure logging
using var loggerFactory = LoggerFactory.Create(builder =>
{
    builder
        .SetMinimumLevel(verbose ? LogLevel.Debug : LogLevel.Information)
        .AddSimpleConsole(options =>
        {
            options.SingleLine = true;
            options.TimestampFormat = null; // No timestamps for CLI output
        });
});

var logger = loggerFactory.CreateLogger<JsonDatabaseSeeder>();

// Create seeder with logger
var seeder = new JsonDatabaseSeeder(seedsPath, logger);

var seedFiles = seeder.GetSeedFiles();

if (seedFiles.Count == 0)
{
    Console.Error.WriteLine($"Error: No seed files found in: {seedsPath}");
    return 1;
}

Console.WriteLine("Database Seed Utility");
Console.WriteLine("=====================");
Console.WriteLine($"Seeds path: {seedsPath}");
Console.WriteLine($"Found {seedFiles.Count} seed file(s):");
foreach (var file in seedFiles)
{
    Console.WriteLine($"  - {file}");
}
Console.WriteLine();

if (dryRun)
{
    Console.WriteLine("[DRY RUN MODE - No changes will be made]");
    Console.WriteLine();
}

if (!force && !dryRun)
{
    Console.Write("Proceed with seeding? (y/n): ");
    var response = Console.ReadLine();
    if (response?.ToLower() != "y" && response?.ToLower() != "yes")
    {
        Console.WriteLine("Aborted.");
        return 1;
    }
}

try
{
    Console.WriteLine("Connecting to database...");
    var results = await seeder.SeedAsync(connectionString, dryRun);

    Console.WriteLine();
    Console.WriteLine("Seeding complete.");

    var totalInserted = results.Sum(r => r.InsertedCount);
    var totalSkipped = results.Sum(r => r.SkippedCount);
    Console.WriteLine($"Total: {totalInserted} inserted, {totalSkipped} skipped");

    return 0;
}
catch (NpgsqlException ex)
{
    Console.Error.WriteLine($"Database error: {ex.Message}");
    return 1;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    return 1;
}
