using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace OneBigHead.Server.Data;

/// <summary>Classifies retryable database races without masking unrelated storage failures.</summary>
public static class DatabaseConcurrency
{
    public static bool IsConflict(Exception exception) => exception is DbUpdateConcurrencyException ||
        exception.GetBaseException() is PostgresException
            { SqlState: PostgresErrorCodes.SerializationFailure or PostgresErrorCodes.DeadlockDetected };
}
