using Npgsql;

// Database Reset Utility
// Drops all tables from the database, optionally preserving migration history

var preserveHistory = args.Contains("--preserve-history");
var force = args.Contains("--force") || args.Contains("-f");
var help = args.Contains("--help") || args.Contains("-h");

if (help)
{
    Console.WriteLine("Database Reset Utility");
    Console.WriteLine();
    Console.WriteLine("Usage: dbreset [options]");
    Console.WriteLine();
    Console.WriteLine("Options:");
    Console.WriteLine("  --force, -f          Skip confirmation prompt");
    Console.WriteLine("  --preserve-history   Keep __EFMigrationsHistory table");
    Console.WriteLine("  --help, -h           Show this help message");
    Console.WriteLine();
    Console.WriteLine("Environment:");
    Console.WriteLine("  ConnectionStrings__DefaultConnection   Database connection string");
    Console.WriteLine();
    Console.WriteLine("Example:");
    Console.WriteLine("  dbreset --force");
    Console.WriteLine("  dbreset --force --preserve-history");
    return 0;
}

// Get connection string from environment (same as main app)
var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__DefaultConnection");

if (string.IsNullOrEmpty(connectionString))
{
    Console.Error.WriteLine("Error: ConnectionStrings__DefaultConnection environment variable not set.");
    Console.Error.WriteLine("This utility uses the same connection string as the main application.");
    return 1;
}

// Parse server/database from connection string for display
var builder = new NpgsqlConnectionStringBuilder(connectionString);
var serverName = builder.Host;
var databaseName = builder.Database;

Console.WriteLine("Database Reset Utility");
Console.WriteLine("======================");
Console.WriteLine($"Server:   {serverName}");
Console.WriteLine($"Database: {databaseName}");
Console.WriteLine($"Preserve migration history: {preserveHistory}");
Console.WriteLine();

if (!force)
{
    Console.Write("WARNING: This will DROP ALL TABLES. Type 'yes' to confirm: ");
    var response = Console.ReadLine();
    if (response?.ToLower() != "yes")
    {
        Console.WriteLine("Aborted.");
        return 1;
    }
}

try
{
    using var connection = new NpgsqlConnection(connectionString);
    await connection.OpenAsync();
    Console.WriteLine("Connected to database.");

    // Get list of tables to drop
    var tables = new List<(string schema, string name)>();
    var listTablesSql = @"
        SELECT table_schema, table_name
        FROM information_schema.tables
        WHERE table_type = 'BASE TABLE'
          AND table_schema NOT IN ('pg_catalog', 'information_schema')";

    if (preserveHistory)
    {
        listTablesSql += " AND table_name != '__EFMigrationsHistory'";
    }

    using (var cmd = new NpgsqlCommand(listTablesSql, connection))
    using (var reader = await cmd.ExecuteReaderAsync())
    {
        while (await reader.ReadAsync())
        {
            tables.Add((reader.GetString(0), reader.GetString(1)));
        }
    }

    if (tables.Count == 0)
    {
        Console.WriteLine("No tables to drop.");
        return 0;
    }

    Console.WriteLine($"Found {tables.Count} table(s) to drop.");

    // Drop tables (CASCADE removes dependent foreign key constraints)
    Console.WriteLine("Dropping tables...");
    foreach (var (schema, name) in tables)
    {
        var dropSql = $"DROP TABLE IF EXISTS \"{schema}\".\"{name}\" CASCADE";
        using var cmd = new NpgsqlCommand(dropSql, connection);
        await cmd.ExecuteNonQueryAsync();
        Console.WriteLine($"  Dropped \"{schema}\".\"{name}\"");
    }

    Console.WriteLine();
    Console.WriteLine("Database reset complete.");

    if (!preserveHistory)
    {
        Console.WriteLine();
        Console.WriteLine("To reapply migrations, run:");
        Console.WriteLine("  /app/efbundle --connection \"$ConnectionStrings__DefaultConnection\"");
    }

    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    return 1;
}
