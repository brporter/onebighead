using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;

namespace OneBigHead.Server.Tests;

/// <summary>
/// IDbContextFactory implementation for tests that creates fresh AppDbContext
/// instances over a shared set of options (typically an in-memory database).
/// </summary>
public sealed class TestDbContextFactory : IDbContextFactory<AppDbContext>
{
    private readonly DbContextOptions<AppDbContext> _options;

    public TestDbContextFactory(DbContextOptions<AppDbContext> options)
    {
        _options = options;
    }

    public AppDbContext CreateDbContext() => new(_options);
}
