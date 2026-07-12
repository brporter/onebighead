using System.Text.Json;
using Microsoft.Extensions.Logging;
using Npgsql;
using NpgsqlTypes;

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
        using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        return await SeedAsync(connection, dryRun);
    }

    /// <summary>
    /// Seeds the database using an existing connection.
    /// </summary>
    /// <param name="connection">Open database connection.</param>
    /// <param name="dryRun">If true, only simulates the seeding without making changes.</param>
    /// <returns>List of results for each table seeded.</returns>
    public async Task<List<SeedResult>> SeedAsync(NpgsqlConnection connection, bool dryRun = false)
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

    private async Task<SeedResult> ProcessTableAsync(NpgsqlConnection connection, SeedTable table, bool dryRun)
    {
        var result = new SeedResult { TableName = table.Name };

        if (table.Rows == null || table.Rows.Count == 0)
        {
            _logger?.LogDebug("Table {TableName}: No rows defined, skipping", table.Name);
            return result;
        }

        var checkColumns = table.GetCheckColumns();

        foreach (var row in table.Rows)
        {
            var columns = row.Keys.ToList();
            var columnList = string.Join(", ", columns.Select(QuoteIdentifier));
            var paramList = string.Join(", ", columns.Select((_, i) => $"@p{i}"));
            var insertSql = $"INSERT INTO {QuoteIdentifier(table.Name)} ({columnList}) VALUES ({paramList})";

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
            using var cmd = new NpgsqlCommand(insertSql, connection);
            for (int i = 0; i < columns.Count; i++)
            {
                AddParameter(cmd, $"p{i}", row[columns[i]]);
            }
            await cmd.ExecuteNonQueryAsync();
            result.InsertedCount++;
        }

        // After inserting explicit identity values, resynchronize the identity
        // sequence so subsequent application inserts don't collide.
        if (table.IdentityInsert && !dryRun && result.InsertedCount > 0)
        {
            await ResyncIdentitySequenceAsync(connection, table);
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
        NpgsqlConnection connection,
        string tableName,
        List<string> checkColumns,
        Dictionary<string, object?> row)
    {
        var whereClauses = checkColumns.Select((c, i) => $"{QuoteIdentifier(c)} = @check{i}");
        var existsSql = $"SELECT COUNT(*) FROM {QuoteIdentifier(tableName)} WHERE {string.Join(" AND ", whereClauses)}";

        using var cmd = new NpgsqlCommand(existsSql, connection);
        for (int i = 0; i < checkColumns.Count; i++)
        {
            AddParameter(cmd, $"check{i}", row[checkColumns[i]]);
        }

        var result = await cmd.ExecuteScalarAsync();
        return result != null && Convert.ToInt64(result) > 0;
    }

    private static async Task ResyncIdentitySequenceAsync(NpgsqlConnection connection, SeedTable table)
    {
        // Seed tables using identity insert provide explicit "Id" values;
        // advance the backing sequence past the highest inserted value.
        const string idColumn = "Id";
        if (!table.Rows.Any(r => r.ContainsKey(idColumn)))
            return;

        var sql = $"""
            SELECT setval(
                pg_get_serial_sequence('{QuoteIdentifier(table.Name)}', '{idColumn}'),
                GREATEST((SELECT COALESCE(MAX({QuoteIdentifier(idColumn)}), 1) FROM {QuoteIdentifier(table.Name)}), 1))
            """;
        using var cmd = new NpgsqlCommand(sql, connection);
        await cmd.ExecuteNonQueryAsync();
    }

    private static void AddParameter(NpgsqlCommand cmd, string name, object? rawValue)
    {
        var value = JsonValueConverter.ConvertJsonElement(rawValue);

        // Strings may target non-text columns (uuid, timestamptz, etc.).
        // NpgsqlDbType.Unknown lets PostgreSQL infer the type from the target column.
        if (value is string)
        {
            cmd.Parameters.Add(new NpgsqlParameter(name, NpgsqlDbType.Unknown) { Value = value });
        }
        else
        {
            cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }
    }

    private static string QuoteIdentifier(string identifier)
        => $"\"{identifier.Replace("\"", "\"\"")}\"";
}
