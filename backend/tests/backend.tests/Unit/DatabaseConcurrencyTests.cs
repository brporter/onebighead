using Microsoft.EntityFrameworkCore;
using Npgsql;
using OneBigHead.Server.Data;

namespace OneBigHead.Server.Tests.Unit;

public class DatabaseConcurrencyTests
{
    [Theory]
    [InlineData(PostgresErrorCodes.SerializationFailure, true)]
    [InlineData(PostgresErrorCodes.DeadlockDetected, true)]
    [InlineData(PostgresErrorCodes.ForeignKeyViolation, false)]
    [InlineData(PostgresErrorCodes.CheckViolation, false)]
    public void DatabaseErrors_AreClassifiedThroughWrapping(string code, bool expected)
    {
        var error = new PostgresException("Test", "ERROR", "ERROR", code);
        Assert.Equal(expected, DatabaseConcurrency.IsConflict(error));
        Assert.Equal(expected, DatabaseConcurrency.IsConflict(new DbUpdateException("Wrapped", error)));
    }

    [Fact]
    public void EfConflictsAreRetryable_ButUnexpectedFailuresAreNot()
    {
        Assert.True(DatabaseConcurrency.IsConflict(new DbUpdateConcurrencyException()));
        Assert.False(DatabaseConcurrency.IsConflict(new InvalidOperationException()));
        Assert.False(DatabaseConcurrency.IsConflict(new DbUpdateException()));
    }
}
