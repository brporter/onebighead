using System.Text.Json;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;

namespace OneBigHead.Server.Services.Seeding;

/// <summary>
/// Seeds the database from JSON definition files.
/// Operates idempotently - skips rows that already exist based on check columns.
/// </summary>
public class JsonDatabaseSeeder
{
    private readonly string _seedsPath;
    private readonly ILogger<JsonDatabaseSeeder>? _logger;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    /// <summary>
    /// Creates a new seeder instance.
    /// </summary>
    /// <param name="seedsPath">Path to the directory containing seed JSON files.</param>
    /// <param name="logger">Optional logger for output.</param>
    public JsonDatabaseSeeder(string seedsPath, ILogger<JsonDatabaseSeeder>? logger = null)
    {
        _seedsPath = seedsPath;
        _logger = logger;
    }

    /// <summary>
    /// Seeds the database using the provided connection string.
    /// </summary>
    /// <param name="connectionString">Database connection string.</param>
    /// <param name="dryRun">If true, only simulates the seeding without making changes.</param>
    /// <returns>List of results for each table seeded.</returns>
    public async Task<List<SeedResult>> SeedAsync(string connectionString, bool dryRun = false)
    {
        using var connection = new SqlConnection(connectionString);
        await connection.OpenAsync();
        return await SeedAsync(connection, dryRun);
    }

    /// <summary>
    /// Seeds the database using an existing connection.
    /// </summary>
    /// <param name="connection">Open database connection.</param>
    /// <param name="dryRun">If true, only simulates the seeding without making changes.</param>
    /// <returns>List of results for each table seeded.</returns>
    public async Task<List<SeedResult>> SeedAsync(SqlConnection connection, bool dryRun = false)
    {
        var results = new List<SeedResult>();

        if (!Directory.Exists(_seedsPath))
        {
            _logger?.LogWarning("Seeds directory not found: {SeedsPath}", _seedsPath);
            return results;
        }

        var seedFiles = Directory.GetFiles(_seedsPath, "*.json").OrderBy(f => f).ToList();

        if (seedFiles.Count == 0)
        {
            _logger?.LogInformation("No seed files found in {SeedsPath}", _seedsPath);
            return results;
        }

        _logger?.LogInformation("Found {Count} seed file(s) in {SeedsPath}", seedFiles.Count, _seedsPath);

        foreach (var seedFile in seedFiles)
        {
            var fileName = Path.GetFileName(seedFile);
            _logger?.LogDebug("Processing seed file: {FileName}", fileName);

            var json = await File.ReadAllTextAsync(seedFile);
            var seedData = JsonSerializer.Deserialize<SeedFile>(json, JsonOptions);

            if (seedData?.Tables == null || seedData.Tables.Count == 0)
            {
                _logger?.LogDebug("No tables defined in {FileName}, skipping", fileName);
                continue;
            }

            foreach (var table in seedData.Tables)
            {
                var result = await ProcessTableAsync(connection, table, dryRun);
                results.Add(result);
            }
        }

        return results;
    }

    /// <summary>
    /// Gets the list of seed files that would be processed.
    /// </summary>
    public List<string> GetSeedFiles()
    {
        if (!Directory.Exists(_seedsPath))
            return new List<string>();

        return Directory.GetFiles(_seedsPath, "*.json")
            .OrderBy(f => f)
            .Select(Path.GetFileName)
            .Where(f => f != null)
            .Cast<string>()
            .ToList();
    }

    private async Task<SeedResult> ProcessTableAsync(SqlConnection connection, SeedTable table, bool dryRun)
    {
        var result = new SeedResult { TableName = table.Name };

        if (table.Rows == null || table.Rows.Count == 0)
        {
            _logger?.LogDebug("Table {TableName}: No rows defined, skipping", table.Name);
            return result;
        }

        var checkColumns = table.GetCheckColumns();

        // Enable identity insert if needed
        if (table.IdentityInsert && !dryRun)
        {
            await ExecuteNonQueryAsync(connection, $"SET IDENTITY_INSERT [{table.Name}] ON");
        }

        try
        {
            foreach (var row in table.Rows)
            {
                var columns = row.Keys.ToList();
                var columnList = string.Join(", ", columns.Select(c => $"[{c}]"));
                var paramList = string.Join(", ", columns.Select((_, i) => $"@p{i}"));
                var insertSql = $"INSERT INTO [{table.Name}] ({columnList}) VALUES ({paramList})";

                if (dryRun)
                {
                    result.InsertedCount++;
                    continue;
                }

                // Check if row exists (idempotent insert)
                if (checkColumns.Count > 0 && checkColumns.All(c => row.ContainsKey(c)))
                {
                    if (await RowExistsAsync(connection, table.Name, checkColumns, row))
                    {
                        result.SkippedCount++;
                        continue;
                    }
                }

                // Insert the row
                using var cmd = new SqlCommand(insertSql, connection);
                for (int i = 0; i < columns.Count; i++)
                {
                    var value = JsonValueConverter.ConvertJsonElement(row[columns[i]]);
                    cmd.Parameters.AddWithValue($"@p{i}", value ?? DBNull.Value);
                }
                await cmd.ExecuteNonQueryAsync();
                result.InsertedCount++;
            }
        }
        finally
        {
            // Disable identity insert
            if (table.IdentityInsert && !dryRun)
            {
                await ExecuteNonQueryAsync(connection, $"SET IDENTITY_INSERT [{table.Name}] OFF");
            }
        }

        if (result.InsertedCount > 0 || result.SkippedCount > 0)
        {
            _logger?.LogInformation(
                "Table {TableName}: Inserted {InsertedCount}, skipped {SkippedCount} existing",
                table.Name, result.InsertedCount, result.SkippedCount);
        }

        return result;
    }

    private async Task<bool> RowExistsAsync(
        SqlConnection connection,
        string tableName,
        List<string> checkColumns,
        Dictionary<string, object?> row)
    {
        var whereClauses = checkColumns.Select((c, i) => $"[{c}] = @check{i}");
        var existsSql = $"SELECT COUNT(*) FROM [{tableName}] WHERE {string.Join(" AND ", whereClauses)}";

        using var cmd = new SqlCommand(existsSql, connection);
        for (int i = 0; i < checkColumns.Count; i++)
        {
            var value = JsonValueConverter.ConvertJsonElement(row[checkColumns[i]]);
            cmd.Parameters.AddWithValue($"@check{i}", value ?? DBNull.Value);
        }

        var result = await cmd.ExecuteScalarAsync();
        return result != null && (int)result > 0;
    }

    private async Task ExecuteNonQueryAsync(SqlConnection connection, string sql)
    {
        using var cmd = new SqlCommand(sql, connection);
        await cmd.ExecuteNonQueryAsync();
    }
}
