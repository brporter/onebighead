using System.Text.Json;
using Microsoft.Extensions.Logging;
using Npgsql;
using NpgsqlTypes;

namespace OneBigHead.Server.Services.Seeding;

/// <summary>
/// Seeds the database from JSON definition files.
/// Operates idempotently and convergently: rows identified by their check
/// columns are inserted when missing and updated to match the seed file when
/// present, so re-running the seeder always converges the database to the
/// current seed files. Each run executes inside a single transaction.
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

        // One transaction per run: a failure in any row rolls back the whole seed.
        await using var transaction = dryRun ? null : await connection.BeginTransactionAsync();

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
                var result = await ProcessTableAsync(connection, transaction, table, dryRun);
                results.Add(result);
            }
        }

        if (transaction != null)
        {
            await transaction.CommitAsync();
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

    private async Task<SeedResult> ProcessTableAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction? transaction,
        SeedTable table,
        bool dryRun)
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
            if (dryRun)
            {
                result.InsertedCount++;
                continue;
            }

            if (checkColumns.Count > 0 && checkColumns.All(c => row.ContainsKey(c)))
            {
                if (await RowExistsAsync(connection, transaction, table.Name, checkColumns, row))
                {
                    // Converge the existing row to the seed file's values.
                    if (await UpdateRowAsync(connection, transaction, table.Name, checkColumns, row))
                    {
                        result.UpdatedCount++;
                    }
                    else
                    {
                        result.SkippedCount++;
                    }
                    continue;
                }
            }

            await InsertRowAsync(connection, transaction, table.Name, row);
            result.InsertedCount++;
        }

        // After inserting explicit identity values, resynchronize the identity
        // sequence so subsequent application inserts don't collide.
        if (table.IdentityInsert && !dryRun && result.InsertedCount > 0)
        {
            await ResyncIdentitySequenceAsync(connection, transaction, table);
        }

        if (result.InsertedCount > 0 || result.UpdatedCount > 0 || result.SkippedCount > 0)
        {
            _logger?.LogInformation(
                "Table {TableName}: Inserted {InsertedCount}, updated {UpdatedCount}, skipped {SkippedCount}",
                table.Name, result.InsertedCount, result.UpdatedCount, result.SkippedCount);
        }

        return result;
    }

    private static async Task InsertRowAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction? transaction,
        string tableName,
        Dictionary<string, object?> row)
    {
        var columns = row.Keys.ToList();
        var columnList = string.Join(", ", columns.Select(QuoteIdentifier));
        var paramList = string.Join(", ", columns.Select((_, i) => $"@p{i}"));
        var insertSql = $"INSERT INTO {QuoteIdentifier(tableName)} ({columnList}) VALUES ({paramList})";

        using var cmd = new NpgsqlCommand(insertSql, connection, transaction);
        for (int i = 0; i < columns.Count; i++)
        {
            AddParameter(cmd, $"p{i}", row[columns[i]]);
        }
        await cmd.ExecuteNonQueryAsync();
    }

    /// <summary>
    /// Updates an existing row's non-identifying columns to the seed values.
    /// Check columns identify the row and are never rewritten; "Id" is never
    /// rewritten because foreign keys may reference the existing value.
    /// Returns false when the row has no updatable columns.
    /// </summary>
    private static async Task<bool> UpdateRowAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction? transaction,
        string tableName,
        List<string> checkColumns,
        Dictionary<string, object?> row)
    {
        var updatableColumns = row.Keys
            .Where(c => !checkColumns.Contains(c, StringComparer.OrdinalIgnoreCase))
            .Where(c => !c.Equals("Id", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (updatableColumns.Count == 0)
        {
            return false;
        }

        var setList = string.Join(", ", updatableColumns.Select((c, i) => $"{QuoteIdentifier(c)} = @s{i}"));
        var whereClauses = checkColumns.Select((c, i) => $"{QuoteIdentifier(c)} = @check{i}");
        var updateSql =
            $"UPDATE {QuoteIdentifier(tableName)} SET {setList} WHERE {string.Join(" AND ", whereClauses)}";

        using var cmd = new NpgsqlCommand(updateSql, connection, transaction);
        for (int i = 0; i < updatableColumns.Count; i++)
        {
            AddParameter(cmd, $"s{i}", row[updatableColumns[i]]);
        }
        for (int i = 0; i < checkColumns.Count; i++)
        {
            AddParameter(cmd, $"check{i}", row[checkColumns[i]]);
        }
        await cmd.ExecuteNonQueryAsync();
        return true;
    }

    private static async Task<bool> RowExistsAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction? transaction,
        string tableName,
        List<string> checkColumns,
        Dictionary<string, object?> row)
    {
        var whereClauses = checkColumns.Select((c, i) => $"{QuoteIdentifier(c)} = @check{i}");
        var existsSql = $"SELECT COUNT(*) FROM {QuoteIdentifier(tableName)} WHERE {string.Join(" AND ", whereClauses)}";

        using var cmd = new NpgsqlCommand(existsSql, connection, transaction);
        for (int i = 0; i < checkColumns.Count; i++)
        {
            AddParameter(cmd, $"check{i}", row[checkColumns[i]]);
        }

        var result = await cmd.ExecuteScalarAsync();
        return result != null && Convert.ToInt64(result) > 0;
    }

    private static async Task ResyncIdentitySequenceAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction? transaction,
        SeedTable table)
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
        using var cmd = new NpgsqlCommand(sql, connection, transaction);
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
