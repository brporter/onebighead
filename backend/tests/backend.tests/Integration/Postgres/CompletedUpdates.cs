using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace OneBigHead.Server.Tests.Integration.Postgres;

internal sealed class CompletedUpdates : DbCommandInterceptor
{
    public List<string> Tables { get; } = [];

    public override ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData eventData,
        DbDataReader result, CancellationToken cancellationToken = default)
    {
        foreach (var table in new[] { "Workspaces", "Users" })
            if (command.CommandText.StartsWith($"UPDATE \"{table}\"", StringComparison.Ordinal)) Tables.Add(table);
        return ValueTask.FromResult(result);
    }
}
