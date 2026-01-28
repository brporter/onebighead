using System.Text.Json;
using Microsoft.Data.SqlClient;

// Database Seed Utility
// Seeds the database with data from external JSON definition files

var seedsPath = args.FirstOrDefault(a => !a.StartsWith("-")) 
    ?? Path.Combine(AppContext.BaseDirectory, "seeds");
var force = args.Contains("--force") || args.Contains("-f");
var dryRun = args.Contains("--dry-run");
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
    Console.WriteLine("  --help, -h           Show this help message");
    Console.WriteLine();
    Console.WriteLine("Environment:");
    Console.WriteLine("  ConnectionStrings__DefaultConnection   Database connection string");
    Console.WriteLine();
    Console.WriteLine("Seed Files:");
    Console.WriteLine("  Seeds are loaded in alphabetical order from the seeds directory.");
    Console.WriteLine("  Each JSON file defines data for one or more tables.");
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

if (!Directory.Exists(seedsPath))
{
    Console.Error.WriteLine($"Error: Seeds directory not found: {seedsPath}");
    return 1;
}

var seedFiles = Directory.GetFiles(seedsPath, "*.json").OrderBy(f => f).ToList();

if (seedFiles.Count == 0)
{
    Console.WriteLine("No seed files found.");
    return 0;
}

Console.WriteLine("Database Seed Utility");
Console.WriteLine("=====================");
Console.WriteLine($"Seeds path: {seedsPath}");
Console.WriteLine($"Found {seedFiles.Count} seed file(s):");
foreach (var file in seedFiles)
{
    Console.WriteLine($"  - {Path.GetFileName(file)}");
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

var jsonOptions = new JsonSerializerOptions
{
    PropertyNameCaseInsensitive = true,
    ReadCommentHandling = JsonCommentHandling.Skip,
    AllowTrailingCommas = true
};

try
{
    using var connection = dryRun ? null : new SqlConnection(connectionString);
    if (connection != null)
    {
        await connection.OpenAsync();
        Console.WriteLine("Connected to database.");
    }
    Console.WriteLine();

    foreach (var seedFile in seedFiles)
    {
        Console.WriteLine($"Processing: {Path.GetFileName(seedFile)}");
        
        var json = await File.ReadAllTextAsync(seedFile);
        var seedData = JsonSerializer.Deserialize<SeedFile>(json, jsonOptions);
        
        if (seedData?.Tables == null || seedData.Tables.Count == 0)
        {
            Console.WriteLine("  No tables defined, skipping.");
            continue;
        }

        foreach (var table in seedData.Tables)
        {
            await ProcessTable(connection, table, dryRun);
        }
    }

    Console.WriteLine();
    Console.WriteLine("Seeding complete.");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    return 1;
}

async Task ProcessTable(SqlConnection? connection, SeedTable table, bool isDryRun)
{
    Console.WriteLine($"  Table: {table.Name}");
    
    if (table.Rows == null || table.Rows.Count == 0)
    {
        Console.WriteLine("    No rows defined, skipping.");
        return;
    }

    // Check if data already exists (if CheckColumn specified)
    if (!string.IsNullOrEmpty(table.CheckColumn) && connection != null)
    {
        var checkSql = $"SELECT COUNT(*) FROM [{table.Name}]";
        using var checkCmd = new SqlCommand(checkSql, connection);
        var result = await checkCmd.ExecuteScalarAsync();
        var count = result != null ? (int)result : 0;
        if (count > 0)
        {
            Console.WriteLine($"    Table already has {count} row(s), skipping (use CheckColumn to control).");
            return;
        }
    }

    // Enable identity insert if needed
    if (table.IdentityInsert && connection != null && !isDryRun)
    {
        using var identityOnCmd = new SqlCommand($"SET IDENTITY_INSERT [{table.Name}] ON", connection);
        await identityOnCmd.ExecuteNonQueryAsync();
    }

    try
    {
        var insertedCount = 0;
        foreach (var row in table.Rows)
        {
            var columns = row.Keys.ToList();
            var columnList = string.Join(", ", columns.Select(c => $"[{c}]"));
            var paramList = string.Join(", ", columns.Select((_, i) => $"@p{i}"));
            
            var insertSql = $"INSERT INTO [{table.Name}] ({columnList}) VALUES ({paramList})";
            
            if (isDryRun)
            {
                var values = string.Join(", ", row.Values.Select(v => v?.ToString() ?? "NULL"));
                Console.WriteLine($"    Would insert: {values}");
            }
            else if (connection != null)
            {
                // Check if row exists (if CheckColumn specified)
                if (!string.IsNullOrEmpty(table.CheckColumn) && row.ContainsKey(table.CheckColumn))
                {
                    var existsSql = $"SELECT COUNT(*) FROM [{table.Name}] WHERE [{table.CheckColumn}] = @check";
                    using var existsCmd = new SqlCommand(existsSql, connection);
                    var checkValue = ConvertJsonElement(row[table.CheckColumn]);
                    existsCmd.Parameters.AddWithValue("@check", checkValue ?? DBNull.Value);
                    var existsResult = await existsCmd.ExecuteScalarAsync();
                    var exists = existsResult != null && (int)existsResult > 0;
                    if (exists)
                    {
                        continue; // Skip existing rows
                    }
                }

                using var cmd = new SqlCommand(insertSql, connection);
                for (int i = 0; i < columns.Count; i++)
                {
                    var value = ConvertJsonElement(row[columns[i]]);
                    cmd.Parameters.AddWithValue($"@p{i}", value ?? DBNull.Value);
                }
                await cmd.ExecuteNonQueryAsync();
                insertedCount++;
            }
        }
        
        if (!isDryRun)
        {
            Console.WriteLine($"    Inserted {insertedCount} row(s).");
        }
    }
    finally
    {
        // Disable identity insert
        if (table.IdentityInsert && connection != null && !isDryRun)
        {
            using var identityOffCmd = new SqlCommand($"SET IDENTITY_INSERT [{table.Name}] OFF", connection);
            await identityOffCmd.ExecuteNonQueryAsync();
        }
    }
}

// Helper to convert JsonElement to native types
static object? ConvertJsonElement(object? value)
{
    if (value is System.Text.Json.JsonElement element)
    {
        return element.ValueKind switch
        {
            System.Text.Json.JsonValueKind.String => element.GetString(),
            System.Text.Json.JsonValueKind.Number => element.TryGetInt32(out var i) ? i : 
                                                      element.TryGetInt64(out var l) ? l : 
                                                      element.GetDouble(),
            System.Text.Json.JsonValueKind.True => true,
            System.Text.Json.JsonValueKind.False => false,
            System.Text.Json.JsonValueKind.Null => null,
            _ => element.ToString()
        };
    }
    return value;
}

// Seed file models
class SeedFile
{
    public List<SeedTable> Tables { get; set; } = new();
}

class SeedTable
{
    public string Name { get; set; } = "";
    public string? CheckColumn { get; set; }
    public bool IdentityInsert { get; set; }
    public List<Dictionary<string, object?>> Rows { get; set; } = new();
}
